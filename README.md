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

### Blind transfer

1. App calls `transfer_call(call_id, target)`; `target` is a dial string (`"1002"`) or a `sip:` URI
2. Engine rejects an empty target or one containing CR, LF, `<` or `>` with `InvalidTarget`, before any network request
3. Engine sends `POST /v1/calls/{token}/transfer` with `{"target": "..."}`; the gateway sends the REFER to the PBX
4. On `202` the local call and media are torn down and `on_call_state_changed` reports `Ended`, as for a remote hangup
5. On failure the call stays up and the method throws: `400` -> `InvalidTarget`, `404` -> `InvalidState` (unknown call, or a gateway without the transfer route), `502` -> `CallFailed` (PBX refused), anything else -> `GatewayError`

## Event contract

Apps can be fully event-driven: install a `MobileEventHandler` with `set_event_handler` and drive the call UI from it instead of polling `get_active_call` or `check_remote_hangup`.

**Threading.** Callbacks can arrive on any thread, including the core's background poll threads, so hop to the main thread before touching UI. A callback may call back into the engine. A callback that throws is contained and does not affect the core.

**Call IDs.** Every `CallInfo` carries a `call_id`. Outgoing calls are `outgoing-<uuid>`; incoming calls are `incoming-<call_token>`, so the ID of an offered call is known from the `CallOffer` before it is answered. Match events to calls by `call_id`; do not treat any `Ended` as ending whichever call is on screen.

**`on_call_state_changed` sequences**

| Flow | Events |
|------|--------|
| Outgoing | `Ringing` (emitted by `make_call` before the gateway is contacted, which is how the app first learns the `call_id`), then `Connected` when the far end answers. If `make_call` fails after `Ringing`, `Ended` follows and the method throws. |
| Incoming | `on_incoming_call(offer)` from `handle_push_notification`, then `Connected` from `accept_incoming_call`. `reject_incoming_call` emits nothing. |
| Caller cancels before answer | `Ended` for `incoming-<call_token>`, detected within about 2 s while the call is unanswered (watched for up to 10 minutes). |
| Mute / hold | `set_mute` re-emits the current state with `muted` updated; `set_hold` emits `OnHold` or `Connected`. |
| Local hangup | `Ended` from `hangup`. |
| Remote hangup (BYE) | `Ended`, emitted by the core within about 2 s of the gateway seeing the BYE. No app polling is needed. |
| Blind transfer | `Ended` once the gateway accepts `transfer_call`. |

**Guarantees.** Each `call_id` that has been reported receives exactly one `Ended`, and nothing after it, whichever of the causes above wins a race. Events triggered by an engine method are emitted before that method returns; remote hangup and caller cancel arrive asynchronously.

**Not carried by events.** `CallInfo` has no end reason; the app knows when it hung up or transferred, and any other `Ended` came from the far side. `duration_secs` is not maintained by the core, so time calls from the `Connected` event.

**Other callbacks.** `on_registration_changed` reports `"registered"` after `register_device` or `update_push_token` succeeds and `"unregistered"` after `unregister_device`. `on_media_stats` and `on_error` are not currently emitted; read `get_media_stats` when stats are needed.

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
