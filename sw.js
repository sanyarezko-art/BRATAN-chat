// BRATAN-chat service worker.
//
// Purpose: make the app installable as a PWA and keep the shell (HTML/CSS/JS)
// available offline so you can at least open existing chats even when the
// network is flaky. Message delivery still requires a live connection to the
// public signaling relays.
//
// Strategy:
//   * precache the small app-shell on install,
//   * network-first for same-origin navigations (so GitHub Pages updates
//     land immediately when the user is online),
//   * cache-first for the static shell assets,
//   * pass-through (don't touch) cross-origin requests — the esm.sh /
//     jsdelivr modules, nostr/mqtt/torrent relays and WebRTC must not be
//     intercepted.

const CACHE_NAME = "bratan-chat-shell-v1";
const SHELL = [
  "./",
  "./index.html",
  "./app.js",
  "./style.css",
  "./manifest.webmanifest",
  "./icon-192.png",
  "./icon-512.png",
  "./icon-maskable-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((c) => c.addAll(SHELL))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((k) => k !== CACHE_NAME)
            .map((k) => caches.delete(k)),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);
  // Ignore cross-origin — relays, ESM CDNs, media blobs, etc.
  if (url.origin !== self.location.origin) return;
  // Don't touch WebSocket / EventSource — they won't hit here anyway, but
  // this is an extra safeguard.
  if (req.headers.get("upgrade") === "websocket") return;

  event.respondWith(
    (async () => {
      // For navigation (HTML) go network-first so the site auto-updates.
      if (req.mode === "navigate") {
        try {
          const fresh = await fetch(req);
          const cache = await caches.open(CACHE_NAME);
          cache.put(req, fresh.clone());
          return fresh;
        } catch {
          const cached = await caches.match(req);
          return cached || caches.match("./index.html");
        }
      }
      // For the static shell: cache-first.
      const cached = await caches.match(req);
      if (cached) return cached;
      try {
        const fresh = await fetch(req);
        const cache = await caches.open(CACHE_NAME);
        if (fresh.ok) cache.put(req, fresh.clone());
        return fresh;
      } catch {
        return caches.match("./index.html");
      }
    })(),
  );
});
