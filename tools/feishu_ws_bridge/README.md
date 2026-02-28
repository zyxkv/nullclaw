# Feishu WebSocket Bridge

This bridge uses the official Feishu/Lark websocket SDK and forwards inbound message events to nullclaw's existing `/lark` webhook route.

## Why this exists

`nullclaw` currently supports Feishu/Lark inbound via webhook. Feishu's websocket protocol uses binary frames and SDK-level ACK/reconnect semantics, so this bridge keeps websocket complexity outside the Zig runtime.

## Prerequisites

1. nullclaw is running with gateway enabled.
2. `channels.lark.accounts.<id>` is configured in nullclaw config (same app credentials).
3. Feishu app event subscription includes `im.message.receive_v1`.
4. Bot capability and required message permissions are enabled in Feishu Open Platform.

## Run

```bash
cd tools/feishu_ws_bridge
go mod tidy
go run .
```

Or from repo root:

```bash
./tools/feishu_ws_bridge/run.sh
```

## Environment variables

- `FEISHU_APP_ID` (required)
- `FEISHU_APP_SECRET` (required)
- `FEISHU_VERIFICATION_TOKEN` (optional but recommended; should match nullclaw lark config)
- `FEISHU_ENCRYPT_KEY` (optional; set if your app uses event encryption)
- `FEISHU_USE_LARKSUITE` (optional, default `false`; set `true` for `open.larksuite.com`)
- `NULLCLAW_LARK_WEBHOOK_URL` (optional, default `http://127.0.0.1:3000/lark`)
- `NULLCLAW_REQUEST_TIMEOUT_SECS` (optional, default `10`)
- `BRIDGE_LOG_LEVEL` (optional: `debug|info|warn|error`, default `info`)

## Notes

- Keep nullclaw Lark receive mode on `webhook` when using this bridge.
- The bridge deduplicates `message_id` for 10 minutes to reduce duplicate replies during reconnect windows.
- This repo also contains a local-only runtime config at `.local-home/.nullclaw/config.json` (gitignored).
