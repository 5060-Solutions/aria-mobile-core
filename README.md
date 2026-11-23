# Aria Mobile Core

Shared Rust engine for the Aria iOS and Android softphone apps. Exposes a cross-platform API via [UniFFI](https://github.com/mozilla/uniffi-rs) that generates native Swift and Kotlin bindings.

## Architecture

```
+------------------+       +------------------+
|    iOS App       |       |   Android App    |
|  (SwiftUI +      |       |  (Compose +      |
|   CallKit)       |       |   ConnectionSvc) |
+--------+---------+       +--------+---------+
         |                          |
    Swift bindings           Kotlin bindings
    (UniFFI generated)       (UniFFI generated)
         |                          |
+--------+--------------------------+---------+
|              aria-mobile-core               |
|                                             |
|  +------------------+  +-----------------+  |
|  | Gateway Client   |  | Media Session   |  |
|  | (REST API)       |  | (SDP + RTP)     |  |
|  +------------------+  +-----------------+  |
|                                             |
|  +------------------+  +-----------------+  |
|  | aria-sip-core    |  | rtp-engine      |  |
|  | (SIP parsing)    |  | (codecs, STUN)  |  |
|  +------------------+  +-----------------+  |
+---------------------------------------------+
```

## Features

- **Push gateway HTTP client** -- device registration, call signaling (accept/reject/hangup/blind and attended transfer), outgoing call initiation
- **SDP generation/parsing** -- offer/answer with codec negotiation (PCMU, PCMA, Opus, G.729)
- **RTP media sessions** -- UDP socket management, STUN discovery, DTMF (RFC 2833)
- **UniFFI bindings** -- type-safe Swift and Kotlin APIs generated from a single UDL definition
- **Async runtime** -- embedded Tokio runtime, bridged to platform threading

## Building

### For host (development/testing)

```bash
cargo build
```

### For iOS

```bash
./build-ios.sh   # in aria-ios/
# Produces XCFramework with aarch64-apple-ios + simulator targets
```

### For Android

```bash
./build-rust.sh  # in aria-android/
# Produces .so libraries for aarch64, armv7, x86_64
```

Requires Android NDK. Set `ANDROID_NDK_HOME` environment variable.

## UniFFI Interface

The API is defined in `src/aria_mobile.udl`. Key types:

- `AriaMobileEngine` -- main engine (create with gateway config, set event handler)
- `MobileEventHandler` -- callback interface for registration/call/media events
- `DeviceRegistration` / `SipCredentials` -- device + SIP account setup
- `CallInfo` / `CallState` -- active call state
- `AudioCodec` -- codec selection (PCMU, PCMA, Opus, G.729)

## Gateway authentication

The core never mints gateway tokens and never calls the gateway's `/v1/auth/token`. Only the PBX holds the issuer key, so the app obtains every gateway token from the PBX and hands it to the core:

1. At PBX device registration (`POST /api/v1/devices`) the response carries `gateway_token`. Pass it as `GatewayConfig.api_key` when constructing `AriaMobileEngine`, then call `register_device`.
2. When the token expires or is revoked (an engine method throws `AuthenticationError`, or `on_auth_required` fires), fetch a new one with `POST /api/v1/devices/{id}/gateway-token` and pass it to `set_gateway_token(token)`. Every later gateway request uses it, including the background call-status polls. `set_gateway_token` does not re-register, so it is safe mid-call.

An engine constructed with an empty `api_key` has no token: methods that need the gateway throw `AuthenticationError` without sending a request until `set_gateway_token` is called.

## Gateway failover

**Which name.** For an `https://` base URL the core looks up the SRV record `_sips._tcp.<gateway host>` (for `http://`, `_sip._tcp.<host>`) through `register_device`. For production that is `_sips._tcp.push.ariaroute.com`. With no SRV records, it uses the base URL's own A/AAAA records on its port (443). Each SRV target becomes one gateway *instance*. Requests to it keep the gateway's domain in the URL, so TLS is checked against `push.ariaroute.com`, while the connection goes to the target's address. So every instance must serve a certificate for the gateway domain. Targets are ordered by priority, and the first one is the *preferred* instance.

**One instance holds the device.** An instance pushes, and places calls for, only devices registered on it, and instances share no state. So the device is registered on exactly one instance at a time. `current_gateway()` returns that instance as `host:port`.

- New calls, incoming-call offers (`handle_push_notification`) and network-change heartbeats go to that instance first. An offer the instance does not know (404) is looked up on the other instances in turn. The registration may have moved after the push was sent.
- **Failover.** When that instance cannot be connected to, the device is registered on the next instance in SRV order, and `on_registration_changed` reports `registered` with the new `device_id`. This happens when a new call is placed, where the call then goes to the new instance, or on a network-change heartbeat. Connect failures are the only trigger, so a request that may have been delivered is never sent twice.
- **Failback.** While the device is on a lower-priority instance, the preferred one is probed with `GET /health`: after 30 s, then 60 s, and so on up to 5 min, each ±20 %. Once it answers and no call is live (connected, ringing or being answered), the device registers there again. The registration on the instance it leaves is then removed (`DELETE /v1/devices/{id}`), and `registered` is reported with the new `device_id`.
- **A live call never moves.** A call lives on one instance. Everything after it is placed or offered (accept, reject, cancel, status polls, hangup, transfer, media updates) goes to that instance, never to whichever is first. A call dialed while another is live is pinned to that call's instance with no failover. The PBX joins two calls in an attended transfer only when both reach it from the same gateway. If a live call's instance stops answering, the call is ended once, with `Ended` and reason `Failed`. That happens after 15 s if another instance answers meanwhile (the instance is gone), or after 60 s in any case. A phone that is itself offline reaches no instance, so a handover or a short outage does not end the call.

`POST /v1/calls` may take up to 45 s, longer than the gateway's 30 s INVITE timeout, so the gateway rather than the client decides that an unanswered call has failed.

## Network changes

Call `notify_network_change()` on every network path change: Wi-Fi to cellular or back, a new IP address, connectivity regained, and when the app returns to the foreground. It returns at once and recovers in the background. A burst of changes is coalesced: one pass runs, then one more if changes arrived meanwhile.

1. **Live calls move first, at once.** For each connected call, held or not:
   - The RTP socket is rebound on the interface that now routes.
   - STUN on the new socket finds its public address. This takes at most 1.5 s; after that the interface address is used.
   - Audio goes out from the new socket from the next 20 ms frame.
   - The core sends the new SDP offer (`POST /v1/calls/{token}/media`) to the call's gateway instance, which re-INVITEs the PBX. The PBX's media relay then sends to and accepts from the new address. The PBX relay does this only from the release with the re-point on re-INVITE; with an older PBX, audio does not resume after a mid-call address change.

   The call is never ended by this, whatever the outcome. A gateway without the route (404) or a PBX refusal is logged, and the call stays up.
2. **The gateway SRV name is looked up again.**
3. **The registration is checked.** The core sends a heartbeat to the instance holding the device, and the gateway re-registers SIP with a fresh flow:
   - If the instance no longer knows the device (404/410), the device registers again.
   - If the instance cannot be reached, the registration fails over (see above).
   - If the token is refused (401), `on_auth_required` fires, and recovery resumes by itself when `set_gateway_token` is called.

Progress is reported through `on_registration_changed(device_id, status, error)`. Apps no longer need to re-register to verify the link.

| `status` | Meaning | Suggested UI |
|---|---|---|
| `recovering` | A network change is being recovered from | "Reconnecting..." (amber), calls continue |
| `registered` | Registered (again). `device_id` is current, and may be new after a move | normal |
| `failed` | Recovery failed; `error` says why. Incoming calls may not arrive until the next network change or `register_device` | "Offline" (red), retry on the next path change |
| `auth_required` | The gateway refused the token. Fetch a new one and call `set_gateway_token` | as `recovering` while the token is fetched |
| `unregistered` | After `unregister_device` | |

Push stays the incoming path in every case. The gateway keeps the SIP registration and wakes the phone through APNs/FCM, so an incoming call reaches a phone whose own sockets are dead or suspended.

`CallInfo.codec` carries the negotiated codec's SDP name (`PCMU`, `PCMA`, `opus`, `G729`) once the call has media.

## One-click setup links

`provision_preview(link)` and `provision_redeem(link)` implement the desktop softphone's setup-link contract, so the same link works on every platform. They are namespace functions: no engine is needed, and they block (call them off the UI thread).

A link is `aria://provision?v=1&url=<percent-encoded https://HOST/provision/softphone/<token>>`. The prefix is matched case-insensitively with an optional `/`; there must be exactly one `v`, equal to `1`, and exactly one non-empty `url`. A legacy QR link (`aria://provision?server=...&user=...`, no `v`) throws `InvalidLink`, so the app falls back to its own parser for it.

1. `provision_preview(link)` sends `GET` to the URL and returns `ProvisionPreview` (tenant, extension, display name, domain, optional expiry, and `server_host`, the `host[:port]` of the setup server). It does not use the link up. Show it, including `server_host`, and ask the user to confirm.
2. Only after the user confirms, `provision_redeem(link)` sends `POST` to the same URL, which uses the link up, and returns `ProvisionedAccount` (username, optional auth username, password, domain, transport, port, optional outbound proxy, voicemail and SRTP mode, tenant and display name, `server_host`). The returned username and domain must equal the previewed extension and domain (domain case-insensitively), or it throws `Mismatch` and nothing should be saved. If the link was not previewed in this process, a preview is fetched first and the redeem is held to that.
3. The app then logs in with `POST /api/v1/auth/extension-login` using `username`, `password` and `domain`, as after a QR scan. Keep the password in the Keychain / Keystore.

Rules, refused before any request with `InvalidLink`: the URL must be `https` (never plain http, not even to localhost), carry no userinfo, and have the path `/provision/softphone/` followed by a non-empty token. While fetching: redirects are not followed (a 3xx is `Server`), each request times out after 10 s (`Network`), replies over 16 KB are refused (`Server`), a 404 means the link expired or was already used (`Expired`), and any other non-200, non-JSON reply, `v` other than 1, or unusable field is `Server`. Fields that end up in SIP headers are checked (extension and username: SIP user characters, at most 64; domain and proxy: host names; password: no control characters); display text has quotes, backslashes, angle brackets and control characters removed. `transport` defaults to `tls`; a `port` of 0 or none means DNS SRV; `outbound_proxy` is normalised to `host` or `host:port` (its own port, else the top-level one). Error messages are written for the user and never contain the link or token; the core never logs them either.

## Call Flows

### Incoming (via push)

1. Push notification wakes app
2. App calls `handle_push_notification(payload)` to fetch SDP offer
3. Platform reports call to CallKit/ConnectionService
4. User answers -> `accept_incoming_call(token, codecs)` -> SDP answer sent to gateway
5. RTP flows directly between app and PBX

### Outgoing (via gateway B2BUA)

1. App picks an id with `new_outgoing_call_id()` and calls `make_call_with_id(id, uri, credentials, codecs)`
2. Engine generates SDP offer, sends to gateway `POST /v1/calls`
3. Gateway sends SIP INVITE to destination
4. Gateway returns SDP answer + call_token
5. Engine updates media session with remote RTP address
6. RTP flows directly between app and PBX

### Hanging up an outgoing call before it is answered

The app picks the call's id before dialing: `id = new_outgoing_call_id()`, then `make_call_with_id(id, uri, credentials, codecs)` on a background thread. The id is `outgoing-` followed by 1-64 characters from `[A-Za-z0-9_-]`. A malformed id, or one that is in use or was used recently, throws `InvalidState`. Because the id is known up front, `hangup(id)` works at any point, and in every case the app sees exactly one `Ended` for the id:

| When `hangup(id)` is called | What happens |
|------|--------|
| Before `make_call_with_id(id, ...)` | `Ended` is reported at once. The later `make_call_with_id` throws `Cancelled` without reporting anything or sending any request. |
| While `make_call_with_id` sets up media or the `POST /v1/calls` is in flight | `Ended` is reported, `make_call_with_id` throws `Cancelled` at once, and if the call was sent, it is cancelled at the gateway in the background, as described below. |
| After the far end answered | An ordinary hangup of an active call. |

Media setup includes STUN discovery of the public address. It is bounded to 4 s in all. Past that, the SDP carries the local interface address, so setup never holds a call up for long. A hangup during setup does not wait for it.

`make_call(uri, ...)` is kept and works as before, with a core-chosen id. With it, the app learns the id only from the `Ringing` event, which is delivered asynchronously on the event thread, so it cannot reliably hang up before then. Prefer `make_call_with_id`.

The gateway assigns a call token only when the far end answers, so a ringing call is cancelled by the call's own reference:

1. `make_call_with_id` sends `"client_ref"` with `POST /v1/calls`: the part of the call's id after `outgoing-`.
2. `hangup` sends `POST /v1/calls/cancel` with `{"client_ref": "..."}`, in the background, to the gateway instance that `POST /v1/calls` went to.
3. `202`: the gateway has sent a SIP CANCEL. The blocked `POST /v1/calls` fails with `409 {"error":"cancelled"}`, and there is nothing more to do. If the far end's 200 OK crossed the CANCEL, the gateway sends the BYE itself, so the core does not hang up again.
4. `404`: the gateway has no ringing call with that ref. It may not have registered the ref yet, because the cancel overtook `POST /v1/calls`. So while that request is still in flight the cancel is retried after 100, 200, 400 and 800 ms. If no retry lands, the call was answered meanwhile or the gateway predates the route. Once `POST /v1/calls` returns a call token, the core immediately sends `POST /v1/calls/{token}/hangup`. The same happens when the cancel fails for any other reason.
5. `401`: `on_auth_required` fires. Step 4's fallback still applies.

A hangup that lands just after the answer works through the same fallback. In every case the gateway gets exactly one accepted cancel or one hangup, and the app sees exactly one `Ended`.

### Blind transfer

1. App calls `transfer_call(call_id, target)`; `target` is a dial string (`"1002"`) or a `sip:` URI
2. Engine rejects an empty target or one containing CR, LF, `<` or `>` with `InvalidTarget`, before any network request
3. Engine sends `POST /v1/calls/{token}/transfer` with `{"target": "..."}`; the gateway sends the REFER to the PBX
4. If the REFER is refused, the call stays up and the method throws: `400` -> `InvalidTarget`, `404` -> `InvalidState` (unknown call, a call not answered yet, or a gateway without the transfer route), `502` -> `CallFailed` (PBX refused), `504` -> `Timeout` (PBX did not answer the REFER within 8 s), anything else -> `GatewayError`
5. A `202` only means the PBX accepted the REFER, and the transfer can still fail. The core polls `GET /v1/calls/{token}/status` every 300 ms for up to 35 s:
   - `{"status":"ended","reason":"transferred"}`: success. The local call and media are torn down, `Ended` is reported, and the method returns.
   - `{"status":"active","transfer":"failed","transfer_code":486}`: the PBX's NOTIFY reported a failure. The method throws `CallFailed`, whose message carries the SIP status, and the call stays fully up with media running, so the caller is not left in dead air.
   - `"transfer":"failed"` with `"transfer_code":408`: no outcome. Either the gateway's 30 s NOTIFY watchdog gave up, or the PBX itself answered 408. The method throws `Timeout`, and the call stays up.
   - No answer from the gateway for 35 s, longer than its watchdog, so this only happens when the gateway stops answering: `Timeout`, with the call still up.
   - Ended for any other reason meanwhile: `Ended` is reported, as for a remote hangup, and the method throws `InvalidState`.
   - An active call with no `transfer` field: a gateway that does not report outcomes. The call is ended on the `202`, as before.

`transfer_call` can block for up to about 45 s (the REFER, then the outcome), so call it off the UI thread. The gateway accepts a bare target of letters, digits and `+*#.-_`, or a `sip:`/`sips:` URI. The core's local check is deliberately looser, so the gateway remains the authority and its refusal surfaces as `InvalidTarget`.

### Attended transfer

1. With a call on hold, the user places a consultation call to the target (`make_call`; the first call is held automatically and the new call goes to the same gateway instance, see above), talks to them, then the app calls `transfer_attended(call_id, consult_call_id)`
2. Engine checks, before any request, that both are distinct connected calls (`InvalidState` otherwise). Each call may be incoming or outgoing, in any combination, and either may be on hold
3. Engine sends `POST /v1/calls/{call_token}/transfer` with `{"replaces": "<consult call_token>"}`; the gateway sends the REFER on `call_id`'s call with `Replaces` naming the consultation call
4. If it is refused, both calls stay up and the method throws: `400 same_call`, `404` and `409 call_not_established` -> `InvalidState`, `409 unsupported_by_pbx` (a gateway or PBX that cannot join these two calls; older PBX releases join only a call the phone received with one it placed) -> `TransferUnsupported`, `409` without a body (a transfer of either call is in progress) -> `GatewayError`, `502` -> `CallFailed`, `504` -> `Timeout`
5. After the `202`, both calls' `/status` is polled as for a blind transfer, and the first verdict on either decides:
   - Both `ended`/`transferred`: each call is reported `Ended` once with reason `Transferred`. If one is reported transferred and the other is still up 5 s later, the other is ended here too (and hung up at the gateway).
   - `"transfer":"failed"`: `CallFailed` with the SIP status (`Timeout` for 408). Both calls stay up as they were.
   - Either call ended for another reason (say the caller hung up mid-transfer): that call is reported `Ended`, the other stays up, and the method throws `InvalidState`.

## Event contract

Apps can be fully event-driven: install a `MobileEventHandler` with `set_event_handler` and drive the call UI from it instead of polling `get_active_call` or `check_remote_hangup`.

**Threading.** Every callback is delivered on one dedicated core thread (`aria-events`), one at a time, never on the thread that called an engine method and never inside the core's async runtime. Hop to the main thread before touching UI. A callback may call any engine method, including the blocking ones (`hangup`, `transfer_call`, `accept_incoming_call`, `make_call_with_id`, ...). While it does, later callbacks wait, so a callback should not block for long. A callback that throws is contained and does not affect the core.

**Call IDs.** Every `CallInfo` carries a `call_id`. Outgoing calls are `outgoing-<id>`, chosen by the app with `new_outgoing_call_id()` and passed to `make_call_with_id`, so the ID is known before dialing. Incoming calls are `incoming-<call_token>`, so the ID of an offered call is known from the `CallOffer` before it is answered. Match events to calls by `call_id`; do not treat any `Ended` as ending whichever call is on screen.

**`on_call_state_changed` sequences**

| Flow | Events | `end_reason` on `Ended` |
|------|--------|------|
| Outgoing | `Ringing` (queued by `make_call_with_id` before media is set up or the gateway is contacted), then `Connected` when the far end answers. If the call fails after `Ringing`, `Ended` follows and the method throws. | `Failed` |
| Outgoing, hung up before it is answered | `Ringing` then `Ended`, or only `Ended` if `hangup(id)` came before `make_call_with_id(id, ...)`. `make_call_with_id` throws `Cancelled`. | `Cancelled` |
| Incoming | `on_incoming_call(offer)` from `handle_push_notification`, then `Connected` from `accept_incoming_call`. | |
| Rejected | `Ended` for `incoming-<call_token>` once `reject_incoming_call` succeeds, for a call offered through `handle_push_notification`. Nothing is reported if the caller had already hung up and that was reported. | `Rejected` |
| Caller cancels before answer | `Ended` for `incoming-<call_token>`, detected within about 2 s while the call is unanswered (watched for up to 10 minutes). | `CallerCancelled` |
| Answered on another device | `Ended` for `incoming-<call_token>`, once the gateway reports the call active while this handset is not accepting it. | `AnsweredElsewhere` |
| Accept with an unknown outcome | `accept_incoming_call` throws `Timeout` or `NetworkError`, and `Ended` is reported for `incoming-<call_token>`. The gateway may have accepted the call anyway, so the core keeps watching it. If it shows up active, the core hangs it up. If it is still ringing, the core rejects it. It is never left connected with nobody on this end. If the gateway refused the accept (an HTTP error), nothing is reported, and the call stays offered. | `Failed` |
| Mute / hold | `set_mute` re-emits the current state with `muted` updated; `set_hold` emits `OnHold` or `Connected`. | |
| Call waiting | When a call connects, or is resumed with `set_hold(id, false)`, every other connected call is put on hold first and reported `OnHold`, just ahead of the new call's `Connected`. `swap_calls(active, held)` reports `OnHold` for the first, then `Connected` for the second. | |
| Conference merge | `conference_merge(a, b)` reports `a` then `b`, each `Connected` with `in_conference` true (a held call is resumed). | |
| Conference split | `conference_split()` reports the older call `OnHold`, then the newer call `Connected`, both with `in_conference` false. | |
| Conference party ends | The surviving call is reported with `in_conference` false and its hold state unchanged (`Connected`, or `OnHold` if the conference was held), just ahead of the other call's `Ended`. | As for that call's flow |
| Recording | `start_recording` re-emits the call with `recording` true, `stop_recording` with `recording` false. A call that ends while recorded carries `recording` false on its `Ended`; the file is already finished. | |
| Local hangup | `Ended` from `hangup`. | `LocalHangup` |
| Remote hangup (BYE) | `Ended`, emitted by the core within about 2 s of the gateway seeing the BYE. No app polling is needed. | From the gateway's `/status` `reason` (see below); `RemoteHangup` by default |
| Blind transfer | `Ended` once the gateway reports the call transferred. A failed or timed-out transfer emits nothing; the call stays up. | `Transferred` |
| Attended transfer | `Ended` for each of the two calls once the gateway reports them transferred. A failed or timed-out transfer emits nothing; both calls stay up. | `Transferred` |

**End reasons.** `CallInfo.end_reason` is set only on the `Ended` event, and is null on every other event. When a call ends at the gateway, the core maps the `reason` from `GET /v1/calls/{token}/status` as follows: `bye_from_remote` -> `RemoteHangup`, `transferred` -> `Transferred`, `cancelled` -> `CallerCancelled`, `rejected` -> `Rejected`, and `no_ack` (the PBX never acknowledged the answer) -> `Failed`. A missing or unrecognised reason, or a call that just disappeared (`unknown` three times in a row), falls back to `RemoteHangup` for an active call and `CallerCancelled` for an offered one. For CallKit: `RemoteHangup`, `Transferred` and `CallerCancelled` -> `.remoteEnded`; `AnsweredElsewhere` -> `.answeredElsewhere`; `Failed` -> `.failed`; `LocalHangup`, `Cancelled` and `Rejected` follow the app's own `hangup` or `reject_incoming_call`, so the app has already reported the end itself. The gateway does not send `rejected` today. The mapping is there so that a decline elsewhere would arrive as `Rejected`. Android's `DisconnectCause` values map the same way (`REMOTE`, `ANSWERED_ELSEWHERE`, `ERROR`, `LOCAL`, `REJECTED`, `CANCELED`).

**Guarantees.** Each `call_id` that has been reported receives exactly one `Ended`, and nothing after it, whichever of the causes above wins a race. A call's events are delivered in the order its state changed, even when the changes come from different threads (for example concurrent `set_hold` and `set_mute`). Delivery is asynchronous: an engine method queues its events before it returns, but the callback may run before or after the method returns, so do not rely on either. Treat the events as the source of truth for call state and the method's return value as the outcome of that request.

**Not carried by events.** `duration_secs` is not maintained by the core, so time calls from the `Connected` event.

**Other callbacks.** `on_registration_changed` reports `"registered"` after `register_device` or `update_push_token` succeeds and `"unregistered"` after `unregister_device`, and the network-change statuses described under "Network changes". `on_auth_required` is described below. `on_error` fires with context `"hangup"` when a call has ended locally but the gateway did not confirm hanging it up, even after one retry on the call's own gateway instance. A 404 is the usual cause: the gateway does not know the call, because it lost it or was asked with the wrong token. The message names the call_id, and the other party may still be connected. `on_media_stats` is not currently emitted; read `get_media_stats` when stats are needed.

**Hangup never blocks.** `hangup` tears the call down locally, queues `Ended` and returns. The gateway hangup, bounded by a 5 s timeout, or the cancel for a ringing call runs in the background. `hangup` throws `AuthenticationError` only when there is no gateway token at all, after ending the call locally and without sending anything.

**Token expiry (`on_auth_required`).** A gateway 401 means the gateway token is missing, expired or revoked. Engine methods that wait on the gateway report it by throwing `AuthenticationError`. Background work cannot throw, so it calls `on_auth_required()` instead. That covers the call-status polls, the caller-cancel watch on an offered incoming call, the network-change heartbeat and media update, `hangup`'s gateway hangup or cancel, and hanging up an outgoing call that was answered after it was cancelled. `on_auth_required` fires at most once per token. It fires again only after `set_gateway_token` has been called and the new token is rejected as well, and a 401 for a token that has already been replaced is ignored. The app should fetch a new token from the PBX (`POST /api/v1/devices/{id}/gateway-token`) and call `set_gateway_token`. A rejected poll never ends a call: the call stays up, polling continues, and it uses the new token once one is set. Until then a remote hangup cannot be detected.

**Call waiting.** Up to two calls can be live at once: connected (held or not), outgoing and ringing, or incoming and being accepted. Outside a conference (below), at most one connected call is off hold; only that call plays to the speaker, reads the microphone and feeds the AI tap, while a held call's RTP keeps flowing (silence out, inbound dropped). Hold is local: no re-INVITE is sent. A third `make_call`, `make_call_with_id` or `accept_incoming_call` throws `InvalidState` without sending or reporting anything, and a refused `make_call_with_id` does not use up its id. Incoming offers are not limited: `handle_push_notification` still returns a third call so the app can show it and `reject_incoming_call` it. When the active call ends, a held call stays held until the app resumes it. `get_calls` lists the live calls, oldest first.

**Conference.** `conference_merge(call_a, call_b)` mixes the two live calls into a local three-way call; there is no PBX conference bridge. Both calls must be connected (held or not) and distinct, and neither may already be in a conference, or it throws `InvalidState` without reporting anything. Both come off hold and get `in_conference` true. The mixing happens in the core, in 20 ms frames: each far end hears the microphone plus the other far end (never itself), and the speaker plays the sum of both far ends. Sums are clamped to the 16-bit range, never wrapped. `call_a` drives the mixer: it reads the microphone and plays the speaker once per frame at its codec rate, and `call_b`'s audio is resampled to and from that rate when the codecs differ (Opus and G.711). Each far end's queued audio is capped at 80 ms, so a leg whose clock runs ahead drops its oldest audio rather than building up delay. While conferenced:
- `set_hold` on either call holds or resumes both (the named call reported first), and they stay a conference. While held, both get silence, and their inbound audio is dropped, as for any held call.
- `set_mute` on either call mutes the shared microphone for both, and both are reported.
- `swap_calls` throws `InvalidState`. Split first.
- `send_dtmf` goes to the named call only.
- `hangup` of either call, a remote BYE, or a blind `transfer_call` of either call ends the conference. The other call leaves the mixer, keeps playing and capturing on its own, and stays `Connected` (or `OnHold` if the conference was held). It is reported with `in_conference` false just before the ended call's `Ended`.
- `transfer_attended(a, b)` of the conferenced pair works as for any two calls: the PBX joins the far ends, and both calls end `Transferred`. The conference ends with the first of them, so the second may first be reported with `in_conference` false and then `Ended`.
- `get_active_call` returns the newer of the two.

`conference_split()` ends the mixing and keeps both calls. The most recently created call stays (or becomes) `Connected`, and the other goes `OnHold`. Both are reported with `in_conference` false, the held one first. It throws `InvalidState` when there is no conference. Mixing a conference into the AI tap works per call: each call's tap gets its own far end, and the microphone goes to `call_a`'s.

**Recording.** `start_recording(call_id, path)` records a connected call (held or not) to a new WAV file at `path`, replacing any file there: 16-bit PCM, mono, at the call's codec rate (8000 Hz for G.711 and G.729, 48000 Hz for Opus). Each 20 ms frame is what was sent to the far end (the microphone, plus the other far end in a conference) mixed with what the far end said, clamped, so a recording of either conferenced call holds all three parties. Held time is silence, and muted time has only the far end, as on the wire. It throws `InvalidState` for an unknown or ringing call or one already being recorded, and `MediaError` if the file cannot be created. `stop_recording(call_id)` finishes the file (final RIFF and data sizes in the header) and returns its path. It throws `InvalidState` if the call is not being recorded, and `MediaError` if a write failed (the file holds what was written before the failure). `is_recording(call_id)` says whether a call is being recorded. A recording stops by itself when its call ends, for any reason, and the file is finished before `Ended` is delivered. Telling the other parties that the call is recorded, where the law requires it, is up to the app.

**Emergency numbers.** `is_emergency_number(dial)` is true for 911, 112, 999 and 000 (the desktop list) after trimming, removing a `sip:`, `sips:` or `tel:` prefix and anything from `@` or `;` on, and removing spaces and dashes. `"9-1-1"` and `"sip:911@pbx"` match. `"+1911"` and `"9111"` do not. Apps must never place these through the gateway: hand them to the native dialer (`tel:`), which can reach the local emergency service with location.

**Polling APIs.** `get_active_call` remains a valid snapshot: the connected call that is off hold, or else the most recently created live call. `check_remote_hangup` still works for apps that poll it, but the `Ended` event has already been delivered by the time an ID appears there, and only the most recent 16 IDs are kept.

## Dependencies

| Crate | Role |
|-------|------|
| `aria-sip-core` | SIP protocol parsing and auth |
| `rtp-engine` | RTP codecs, STUN discovery (no `device` feature -- no native audio) |
| `uniffi` | Cross-language binding generation |
| `reqwest` | HTTP client for gateway API |
| `tokio` | Async runtime |

## Ecosystem

| Component | Repository |
|-----------|-----------|
| Desktop softphone | [aria](https://github.com/5060-Solutions/aria) |
| RTP media engine | [rtp-engine](https://github.com/5060-Solutions/rtp-engine) |
| SIP protocol library | [aria-sip-core](https://github.com/5060-Solutions/aria-sip-core) |
| Push gateway | [aria-push-gateway](https://github.com/5060-Solutions/aria-push-gateway) |
| **Mobile core** | **aria-mobile-core** |
| iOS app | [aria-ios](https://github.com/5060-Solutions/aria-ios) |
| Android app | [aria-android](https://github.com/5060-Solutions/aria-android) |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
