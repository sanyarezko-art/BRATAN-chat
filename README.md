# tailscale-chat

A minimal, self-hosted web chat that lives **inside your Tailscale tailnet**.
The server joins the tailnet as a userspace node using
[`tsnet`](https://tailscale.com/kb/1244/tsnet), so the chat is only reachable
by machines already on your tailnet. Users are identified automatically via
the Tailscale `WhoIs` RPC — no separate accounts, passwords, or OAuth flow.

## Features

- Single Go binary, no external database (append-only JSON Lines log).
- Real-time messaging over WebSockets.
- Identity is inferred from the Tailscale tailnet (display name + login).
- History (last N messages) is replayed to each new client on connect.
- Automatic reconnect in the browser.
- Light/dark theme based on OS preference.

## Quick start

1. Create a Tailscale **auth key** at
   <https://login.tailscale.com/admin/settings/keys>
   (reusable + ephemeral is fine for testing).
2. Build and run:

   ```sh
   export TS_AUTHKEY=tskey-auth-xxxxxxxxxxxx
   go run . -hostname chat
   ```

3. The first run registers a new node called `chat` in your tailnet. Once
   it's up the log will print the tailnet URLs, e.g.:

   ```
   tailscale-chat up on http://chat (tailnet: example.ts.net)
     also reachable at http://100.64.0.42:80
   ```

4. On any other tailnet-joined device, open `http://chat/` (or the
   `http://<tailscale-ip>/` URL). You should see the chat and your name
   at the top right.

## Flags

| Flag          | Default           | Description                                          |
| ------------- | ----------------- | ---------------------------------------------------- |
| `-hostname`   | `chat`            | Tailscale hostname advertised by this node.          |
| `-state-dir`  | `./tsnet-state`   | Where `tsnet` stores node state (keys, certs).       |
| `-db`         | `./chat.jsonl`    | Append-only JSON Lines log of messages.              |
| `-addr`       | `:80`             | Address to listen on inside the tailnet.             |
| `-history`    | `200`             | Messages kept in memory / replayed on connect.       |

## How identity works

Every HTTP request that arrives at the tsnet listener comes from a known
tailnet peer. The server calls `LocalClient.WhoIs(remoteAddr)` on each
request and uses the returned `UserProfile.DisplayName` and `LoginName`
as the author of any messages sent over that WebSocket. Clients cannot
spoof their identity because the remote address is validated inside
tsnet — it is not an HTTP header the client controls.

## Persistence

Messages are appended to `chat.jsonl` (one JSON object per line). On
startup the file is replayed into an in-memory ring buffer of the last
`-history` messages. Delete the file to wipe history.

## Production notes

- Pass `TS_AUTHKEY` via a secrets manager or systemd credential, not the
  shell history.
- Use an ephemeral, tagged auth key so the chat node is automatically
  removed from your tailnet if it goes away.
- Bind to `:443` and call `srv.ListenTLS` (not shown here) to get an
  automatic Let's Encrypt cert from Tailscale's `GetCertificate`.
- Put the binary behind systemd (`Restart=on-failure`) on whichever
  machine you want to host it on.

## License

MIT — see [LICENSE](./LICENSE).
