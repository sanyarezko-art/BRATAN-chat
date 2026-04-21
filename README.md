# BRATAN-chat

End-to-end encrypted, peer-to-peer web chat. **No server. No accounts. No history.**
100% static site hosted on GitHub Pages.

## How it works

- You create a room. A **32-byte random secret** is generated in your browser.
- The secret is placed in the URL fragment (`https://.../#<base64>`). Fragments
  are **never sent to any server**, so the secret stays client-side.
- The secret is used to derive two things locally via SHA-256:
  - `roomId` = used by [Trystero](https://github.com/trystero-p2p/trystero) to find
    other peers through public BitTorrent trackers.
  - `password` = given to Trystero, which runs PBKDF2 + AES-GCM on every
    message on top of the already-encrypted WebRTC data channel.
- Peers connect **directly to each other** over WebRTC (DTLS-SRTP). Trackers
  never see message contents — they see only the SHA-256-derived `roomId`.
- Share the invite link with the people you want in the room. Anyone with
  the link can join. Anyone without it cannot.

## Threat model

Be honest with yourself about what this gives you:

- **What's protected:** message contents in flight, room membership (trackers
  only see a hash), message history at rest (there is none — nothing is
  persisted outside your browser tab).
- **What's NOT protected:**
  - Anyone with the invite link can read and send messages in that room.
    Treat the link as a password. Use a fresh room + fresh link per
    conversation.
  - Nicknames are self-reported. Any peer in the room can claim any
    nickname. Don't use nicknames to authenticate identities.
  - Public BT trackers learn your IP address and the roomId hash. Use a VPN
    if you care about IP privacy.
  - Closing the tab drops the session. There is no "read it later".

## Running it locally

It's a static site. Any HTTP server works:

```sh
python3 -m http.server 8080
# open http://localhost:8080/
```

`app.js` loads Trystero from [esm.sh](https://esm.sh/) so no build step is
needed.

## Deployed on GitHub Pages

Pushes to `main` are served from the repo root at
<https://sanyarezko-art.github.io/BRATAN-chat/>.

## License

MIT — see [LICENSE](./LICENSE).
