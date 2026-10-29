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

- **Push gateway HTTP client** -- device registration, call signaling (accept/reject/hangup/blind transfer), outgoing call initiation
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

When the gateway domain has SRV records, `register_device` resolves them into an ordered list of gateway instances. A request moves to the next instance only when it could not connect, so it was certainly never delivered. A timeout or a reset after sending is returned as an error instead, so a non-idempotent request such as `POST /v1/calls` is never sent twice and the callee never rings twice. A call lives on one instance. Everything after it is placed or offered (accept, reject, cancel, status polls, hangup, transfer) goes to that instance, never to whichever one is first. `POST /v1/calls` may take up to 45 s, longer than the gateway's 30 s INVITE timeout, so the gateway rather than the client decides that an unanswered call has failed.

## Call Flows

### Incoming (via push)

1. Push notification wakes app
2. App calls `handle_push_notification(payload)` to fetch SDP offer
3. Platform reports call to CallKit/ConnectionService
4. User answers -> `accept_incoming_call(token, codecs)` -> SDP answer sent to gateway
5. RTP flows directly between app and PBX

### Outgoing (via gateway B2BUA)

1. App calls `make_call(uri, credentials, codecs)`
2. Engine generates SDP offer, sends to gateway `POST /v1/calls`
3. Gateway sends SIP INVITE to destination
4. Gateway returns SDP answer + call_token
5. Engine updates media session with remote RTP address
6. RTP flows directly between app and PBX

### Hanging up while an outgoing call rings

`make_call` blocks until the far end answers, but the call can be hung up before then. Call `hangup(call_id)` with the `call_id` from the `Ringing` event. `hangup` returns at once, `Ended` is reported, `make_call` throws `Cancelled`, and the cancel is sent to the gateway in the background.

The gateway assigns a call token only when the far end answers, so a ringing call is cancelled by a reference of the core's own choosing:

1. `make_call` sends `"client_ref"` with `POST /v1/calls`: the uuid part of the call's `outgoing-<uuid>` id.
2. `hangup` sends `POST /v1/calls/cancel` with `{"client_ref": "..."}`, in the background, to the gateway instance that `POST /v1/calls` went to.
3. `202`: the gateway has sent a SIP CANCEL. The blocked `POST /v1/calls` fails with `409 {"error":"cancelled"}`, and there is nothing more to do. If the far end's 200 OK crossed the CANCEL, the gateway sends the BYE itself, so the core does not hang up again.
4. `404`: the gateway has no ringing call with that ref. It may not have registered the ref yet, because the cancel overtook `POST /v1/calls`. So while that request is still in flight the cancel is retried after 100, 200, 400 and 800 ms. If no retry lands, the call was answered meanwhile or the gateway predates the route. Once `POST /v1/calls` returns a call token, the core immediately sends `POST /v1/calls/{token}/hangup`. The same happens when the cancel fails for any other reason.
5. `401`: `on_auth_required` fires. Step 4's fallback still applies.

A hangup that lands just after the answer works through the same fallback. In every case the gateway gets exactly one accepted cancel or one hangup, and the app sees exactly one `Ended`.

### Blind transfer

1. App calls `transfer_call(call_id, target)`; `target` is a dial string (`"1002"`) or a `sip:` URI
2. Engine rejects an empty target or one containing CR, LF, `<` or `>` with `InvalidTarget`, before any network request
3. Engine sends `POST /v1/calls/{token}/transfer` with `{"target": "..."}`; the gateway sends the REFER to the PBX
4. On `202` the local call and media are torn down and `on_call_state_changed` reports `Ended`, as for a remote hangup
5. On failure the call stays up and the method throws: `400` -> `InvalidTarget`, `404` -> `InvalidState` (unknown call, a call not answered yet, or a gateway without the transfer route), `502` -> `CallFailed` (PBX refused), `504` -> `Timeout` (PBX did not answer the REFER within 8 s), anything else -> `GatewayError`

`transfer_call` can block for up to about 8 s while the gateway waits on the PBX, so call it off the UI thread. The gateway accepts a bare target of letters, digits and `+*#.-_`, or a `sip:`/`sips:` URI. The core's local check is deliberately looser, so the gateway remains the authority and its refusal surfaces as `InvalidTarget`. After a `202` the PBX finishes the transfer and the gateway reports the call as ended with reason `transferred`. The core ends the local call as soon as the `202` arrives, without waiting for that.

## Event contract

Apps can be fully event-driven: install a `MobileEventHandler` with `set_event_handler` and drive the call UI from it instead of polling `get_active_call` or `check_remote_hangup`.

**Threading.** Every callback is delivered on one dedicated core thread (`aria-events`), one at a time, never on the thread that called an engine method and never inside the core's async runtime. Hop to the main thread before touching UI. A callback may call any engine method, including the blocking ones (`hangup`, `transfer_call`, `accept_incoming_call`, `make_call`, ...). While it does, later callbacks wait, so a callback should not block for long. A callback that throws is contained and does not affect the core.

**Call IDs.** Every `CallInfo` carries a `call_id`. Outgoing calls are `outgoing-<uuid>`; incoming calls are `incoming-<call_token>`, so the ID of an offered call is known from the `CallOffer` before it is answered. Match events to calls by `call_id`; do not treat any `Ended` as ending whichever call is on screen.

**`on_call_state_changed` sequences**

| Flow | Events |
|------|--------|
| Outgoing | `Ringing` (emitted by `make_call` before the gateway is contacted, which is how the app first learns the `call_id`), then `Connected` when the far end answers. If `make_call` fails after `Ringing`, `Ended` follows and the method throws. |
| Outgoing, hung up while ringing | `Ringing`, then `Ended` from `hangup(call_id)`. The blocked `make_call` then throws `Cancelled`. |
| Incoming | `on_incoming_call(offer)` from `handle_push_notification`, then `Connected` from `accept_incoming_call`. `reject_incoming_call` emits nothing. |
| Caller cancels before answer | `Ended` for `incoming-<call_token>`, detected within about 2 s while the call is unanswered (watched for up to 10 minutes). |
| Mute / hold | `set_mute` re-emits the current state with `muted` updated; `set_hold` emits `OnHold` or `Connected`. |
| Local hangup | `Ended` from `hangup`. |
| Remote hangup (BYE) | `Ended`, emitted by the core within about 2 s of the gateway seeing the BYE. No app polling is needed. |
| Blind transfer | `Ended` once the gateway accepts `transfer_call`. |

**Guarantees.** Each `call_id` that has been reported receives exactly one `Ended`, and nothing after it, whichever of the causes above wins a race. A call's events are delivered in the order its state changed, even when the changes come from different threads (for example concurrent `set_hold` and `set_mute`). Delivery is asynchronous: an engine method queues its events before it returns, but the callback may run before or after the method returns, so do not rely on either. Treat the events as the source of truth for call state and the method's return value as the outcome of that request.

**Not carried by events.** `CallInfo` has no end reason; the app knows when it hung up or transferred, and any other `Ended` came from the far side. `duration_secs` is not maintained by the core, so time calls from the `Connected` event.

**Other callbacks.** `on_registration_changed` reports `"registered"` after `register_device` or `update_push_token` succeeds and `"unregistered"` after `unregister_device`. `on_auth_required` is described below. `on_error` fires with context `"hangup"` when a call has ended locally but the gateway did not confirm hanging it up, even after one retry on the call's own gateway instance. A 404 is the usual cause: the gateway does not know the call, because it lost it or was asked with the wrong token. The message names the call_id, and the other party may still be connected. `on_media_stats` is not currently emitted; read `get_media_stats` when stats are needed.

**Hangup never blocks.** `hangup` tears the call down locally, queues `Ended` and returns. The gateway hangup, bounded by a 5 s timeout, or the cancel for a ringing call runs in the background. `hangup` throws `AuthenticationError` only when there is no gateway token at all, after ending the call locally and without sending anything.

**Token expiry (`on_auth_required`).** A gateway 401 means the gateway token is missing, expired or revoked. Engine methods that wait on the gateway report it by throwing `AuthenticationError`. Background work cannot throw, so it calls `on_auth_required()` instead. That covers the call-status polls, the caller-cancel watch on an offered incoming call, the network-change heartbeat, `hangup`'s gateway hangup or cancel, and hanging up an outgoing call that was answered after it was cancelled. `on_auth_required` fires at most once per token. It fires again only after `set_gateway_token` has been called and the new token is rejected as well, and a 401 for a token that has already been replaced is ignored. The app should fetch a new token from the PBX (`POST /api/v1/devices/{id}/gateway-token`) and call `set_gateway_token`. A rejected poll never ends a call: the call stays up, polling continues, and it uses the new token once one is set. Until then a remote hangup cannot be detected.

**Polling APIs.** `get_active_call` remains a valid snapshot. `check_remote_hangup` still works for apps that poll it, but the `Ended` event has already been delivered by the time an ID appears there, and only the most recent 16 IDs are kept.

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
