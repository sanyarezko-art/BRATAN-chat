// BRATAN-chat: E2EE P2P-мессенджер на GitHub Pages.
//
// Модель:
//   - Каждая комната = 32-байтный случайный секрет, сгенерированный у тебя
//     в браузере. Из него выводятся:
//       * roomId = hex(SHA-256(secret || "bratan-chat/room/v1"))
//         — то, что отправляется в публичные signaling-сети (nostr-relays,
//         BT-WSS-трекеры) для обнаружения пиров. Они видят хэш, не секрет.
//       * password = base64(SHA-256(secret || "bratan-chat/password/v1"))
//         — Trystero выводит из него AES-GCM ключ (PBKDF2) и шифрует каждый
//         пакет в data-channel поверх родного DTLS-SRTP WebRTC.
//   - Секрет лежит только во фрагменте URL (#…) и в localStorage твоего
//     браузера (список чатов). На сервер никогда не уходит.
//   - Медиа шифруются тем же ключом, передаются бинарём по тем же
//     data-channel; Trystero авто-чанкует.
//
// Модель угроз (честно):
//   - Кто имеет ссылку — у того полный доступ. Относись к ссылке как к паролю.
//   - Ники — самоназвания, любой может представиться кем угодно.
//   - Публичные relays/трекеры видят IP пиров. Если паранойя — через VPN/Tor.
//   - localStorage держит секреты; физический доступ к твоему браузеру =
//     доступ к чатам. В настройках есть кнопка "стереть всё".

import {joinRoom as joinNostr, selfId} from "https://esm.sh/@trystero-p2p/nostr@0.23.1";
import {joinRoom as joinTorrent} from "https://esm.sh/@trystero-p2p/torrent@0.23.1";
import {GIFEncoder, quantize, applyPalette} from "https://cdn.jsdelivr.net/npm/gifenc@1.0.3/+esm";

const APP_ID = "bratan-chat/v1";
const ROOM_SALT = "bratan-chat/room/v1";
const PASSWORD_SALT = "bratan-chat/password/v1";
const STORAGE_KEY = "bratan.chats.v1";
const NICK_KEY = "bratan.nick";

const MEDIA_MAX_WIDTH = 320;
const MEDIA_MAX_DURATION_SEC = 5;
const MEDIA_FPS = 10;
const MEDIA_MAX_INPUT_BYTES = 50 * 1024 * 1024;

const AVATAR_EMOJI = [
  "🦊", "🐻", "🐼", "🐯", "🦁", "🐶", "🐵", "🦄",
  "🐙", "🐢", "🐳", "🐬", "🐸", "🐨", "🦉", "🐰",
  "🦝", "🐺", "🐮", "🐷", "🦔", "🦦", "🐧", "🦩",
  "🐲", "🦖", "🦕", "🐝", "🦋", "🌵", "🍄", "⚡️",
];
const ROOM_EMOJI = [
  "🤝", "🌈", "🌌", "🎆", "🔥", "⚡️", "💎", "🚀",
  "🎸", "🎮", "🎲", "🍕", "☕️", "🌊", "🌙", "🪐",
];

// --- small utils ------------------------------------------------------------

const $ = (id) => document.getElementById(id);
const textEncoder = new TextEncoder();

const b64urlEncode = (bytes) => {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
};
const b64urlDecode = (str) => {
  const pad = "=".repeat((4 - (str.length % 4)) % 4);
  const s = (str + pad).replaceAll("-", "+").replaceAll("_", "/");
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

async function sha256(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}
const toHex = (bytes) =>
  [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");

async function deriveRoomId(bytes) {
  return toHex(await sha256(bytes, textEncoder.encode(ROOM_SALT)));
}
async function derivePassword(bytes) {
  return b64urlEncode(await sha256(bytes, textEncoder.encode(PASSWORD_SALT)));
}

function pickFromList(key, list) {
  let hash = 2166136261;
  for (let i = 0; i < key.length; i++) {
    hash ^= key.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return list[Math.abs(hash) % list.length];
}
const avatarFor = (peerId) => pickFromList(peerId || "self", AVATAR_EMOJI);
const roomEmojiFor = (key) => pickFromList(key || "room", ROOM_EMOJI);

function generateSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return {bytes, str: b64urlEncode(bytes)};
}

function inviteUrl(secretStr) {
  return `${location.origin}${location.pathname}#${secretStr}`;
}

function parseInvite(text) {
  const trimmed = String(text || "").trim();
  if (!trimmed) return null;
  let secret;
  try {
    const url = new URL(trimmed);
    secret = url.hash.replace(/^#/, "");
  } catch {
    secret = trimmed.replace(/^#/, "");
  }
  if (!secret) return null;
  try {
    const bytes = b64urlDecode(secret);
    if (bytes.length < 16) return null;
    return {secret, bytes};
  } catch {
    return null;
  }
}

function fmtTime(ts) {
  return new Date(ts).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

function randomId() {
  const b = crypto.getRandomValues(new Uint8Array(8));
  return toHex(b);
}

// --- app state --------------------------------------------------------------

const state = {
  chats: new Map(), // chatId -> ChatSession (chatId = roomId)
  activeId: null,
  nick: localStorage.getItem(NICK_KEY) || "",
  pendingMediaJob: null, // {cancel}
};

// --- persistence ------------------------------------------------------------

function loadChatIndex() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    return arr.filter(
      (c) =>
        c &&
        typeof c.secretStr === "string" &&
        typeof c.id === "string",
    );
  } catch {
    return [];
  }
}

function saveChatIndex() {
  const arr = [...state.chats.values()].map((c) => ({
    id: c.id,
    secretStr: c.secretStr,
    name: c.name || "",
    createdAt: c.createdAt,
  }));
  localStorage.setItem(STORAGE_KEY, JSON.stringify(arr));
}

// --- ChatSession ------------------------------------------------------------

function createSession({id, secretStr, secretBytes, password, name, createdAt}) {
  return {
    id, // = roomId (hex)
    secretStr,
    secretBytes,
    password,
    name: name || "",
    createdAt: createdAt || Date.now(),
    rooms: [], // Trystero rooms from both strategies
    sendMsg: null,
    sendMedia: null,
    sendNick: null,
    peerNames: new Map(), // peerId -> nick
    messages: [], // {id, from, nick, ts, self, kind: 'text'|'media', text?, media?, state?}
    unread: 0,
    searchingSince: 0,
    seenMsgs: new Set(),
    mediaBlobs: new Map(), // mediaId -> blobUrl
  };
}

async function startSession(sess) {
  const strategies = [
    {name: "nostr", join: joinNostr},
    {name: "torrent", join: joinTorrent},
  ];
  const sendMsgFns = [];
  const sendMediaFns = [];
  const sendNickFns = [];

  for (const {join} of strategies) {
    let room;
    try {
      room = join({appId: APP_ID, password: sess.password}, sess.id);
    } catch (e) {
      console.warn("joinRoom failed", e);
      continue;
    }
    sess.rooms.push(room);

    const [sendMsg, getMsg] = room.makeAction("msg");
    const [sendMedia, getMedia, onMediaProgress] = room.makeAction("media");
    const [sendNick, getNick] = room.makeAction("nick");
    sendMsgFns.push(sendMsg);
    sendMediaFns.push(sendMedia);
    sendNickFns.push(sendNick);

    room.onPeerJoin((peerId) => {
      if (!sess.peerNames.has(peerId)) {
        sess.peerNames.set(peerId, peerId.slice(0, 6));
        pushSystem(sess, `${avatarFor(peerId)} ${peerId.slice(0, 6)}… подключился 🤝`);
      }
      renderChatIfActive(sess);
      renderSidebar();
      try {
        sendNick(state.nick, peerId);
      } catch {}
    });

    room.onPeerLeave((peerId) => {
      setTimeout(() => {
        const stillHere = sess.rooms.some((r) => {
          try {
            const peers = r.getPeers ? r.getPeers() : {};
            return peerId in peers;
          } catch {
            return false;
          }
        });
        if (stillHere) return;
        const name = sess.peerNames.get(peerId) || peerId.slice(0, 6);
        if (sess.peerNames.delete(peerId)) {
          pushSystem(sess, `👋 ${name} вышел`);
        }
        renderChatIfActive(sess);
        renderSidebar();
      }, 500);
    });

    getNick((nick, peerId) => {
      const clean = String(nick || "").slice(0, 32) || peerId.slice(0, 6);
      const prev = sess.peerNames.get(peerId);
      sess.peerNames.set(peerId, clean);
      const wasInitial = prev && prev === peerId.slice(0, 6);
      if (prev && prev !== clean && !wasInitial) {
        pushSystem(sess, `${avatarFor(peerId)} ${prev} теперь ${clean}`);
        renderChatIfActive(sess);
      }
    });

    getMsg((payload, peerId) => {
      if (!payload || typeof payload !== "object") return;
      const text = String(payload.text || "").slice(0, 4000);
      const ts = Number(payload.ts) || Date.now();
      const msgId = String(payload.id || "") || `${peerId}|${ts}`;
      if (!text) return;
      const dedupKey = `t:${peerId}|${ts}|${text}`;
      if (sess.seenMsgs.has(dedupKey)) return;
      sess.seenMsgs.add(dedupKey);
      trimSet(sess.seenMsgs, 500);

      const nick = sess.peerNames.get(peerId) || peerId.slice(0, 6);
      pushMessage(sess, {
        id: msgId,
        from: peerId,
        nick,
        ts,
        self: false,
        kind: "text",
        text,
      });
    });

    getMedia((payload, peerId) => {
      if (!payload || typeof payload !== "object") return;
      const bytes = payload.bytes;
      if (!(bytes instanceof Uint8Array)) return;
      const mime = String(payload.mime || "image/gif");
      const ts = Number(payload.ts) || Date.now();
      const mediaId = String(payload.mediaId || "") || randomId();
      const w = Math.max(1, Math.min(2048, Number(payload.w) || 320));
      const h = Math.max(1, Math.min(2048, Number(payload.h) || 320));
      const dedupKey = `m:${peerId}|${mediaId}`;
      if (sess.seenMsgs.has(dedupKey)) return;
      sess.seenMsgs.add(dedupKey);
      trimSet(sess.seenMsgs, 500);

      const blob = new Blob([bytes], {type: mime});
      const url = URL.createObjectURL(blob);
      sess.mediaBlobs.set(mediaId, url);
      const nick = sess.peerNames.get(peerId) || peerId.slice(0, 6);
      pushMessage(sess, {
        id: mediaId,
        from: peerId,
        nick,
        ts,
        self: false,
        kind: "media",
        media: {url, mime, w, h, size: bytes.length},
      });
    });

    if (onMediaProgress) {
      onMediaProgress((percent, peerId, meta) => {
        // We could show download progress for incoming media here; skipped for
        // simplicity.
      });
    }
  }

  sess.sendMsg = (payload) => {
    for (const fn of sendMsgFns) {
      try {
        fn(payload);
      } catch {}
    }
  };
  sess.sendMedia = async (payload, onProgress) => {
    const promises = sendMediaFns.map((fn) => {
      try {
        return fn(payload, null, null, onProgress);
      } catch (e) {
        return Promise.resolve();
      }
    });
    await Promise.allSettled(promises);
  };
  sess.sendNick = (nick, peerId) => {
    for (const fn of sendNickFns) {
      try {
        fn(nick, peerId);
      } catch {}
    }
  };

  sess.searchingSince = Date.now();
  renderChatIfActive(sess);
  renderSidebar();
}

async function stopSession(sess) {
  for (const r of sess.rooms) {
    try {
      await r.leave();
    } catch {}
  }
  sess.rooms = [];
  for (const url of sess.mediaBlobs.values()) {
    try {
      URL.revokeObjectURL(url);
    } catch {}
  }
  sess.mediaBlobs.clear();
}

function trimSet(set, max) {
  if (set.size > max) {
    const arr = [...set];
    set.clear();
    for (const v of arr.slice(-Math.floor(max / 2))) set.add(v);
  }
}

// --- message/chat helpers ---------------------------------------------------

function pushMessage(sess, msg) {
  sess.messages.push(msg);
  if (sess.messages.length > 500) sess.messages = sess.messages.slice(-400);
  if (sess.id !== state.activeId) {
    sess.unread += 1;
  } else {
    renderMessageAppend(sess, msg);
  }
  renderSidebar();
}

function pushSystem(sess, text) {
  sess.messages.push({
    id: randomId(),
    kind: "sys",
    ts: Date.now(),
    text,
  });
  if (sess.id === state.activeId) {
    renderMessageAppend(sess, sess.messages[sess.messages.length - 1]);
  }
}

async function createChatFromSecret(secretStr, secretBytes, {name} = {}) {
  const [id, password] = await Promise.all([
    deriveRoomId(secretBytes),
    derivePassword(secretBytes),
  ]);
  const existing = state.chats.get(id);
  if (existing) return existing;
  const sess = createSession({
    id,
    secretStr,
    secretBytes,
    password,
    name: name || "",
    createdAt: Date.now(),
  });
  state.chats.set(id, sess);
  saveChatIndex();
  await startSession(sess);
  return sess;
}

async function removeChat(id) {
  const sess = state.chats.get(id);
  if (!sess) return;
  await stopSession(sess);
  state.chats.delete(id);
  saveChatIndex();
  if (state.activeId === id) {
    setActiveChat(null);
  }
  renderSidebar();
}

// --- rendering: sidebar -----------------------------------------------------

function renderSidebar() {
  const list = $("chat-list");
  const empty = $("sidebar-empty");
  const chats = [...state.chats.values()].sort(
    (a, b) => lastActivity(b) - lastActivity(a),
  );
  if (chats.length === 0) {
    list.innerHTML = "";
    empty.hidden = false;
  } else {
    empty.hidden = true;
    list.innerHTML = "";
    for (const c of chats) {
      const li = document.createElement("li");
      li.className = "chat-item";
      if (c.id === state.activeId) li.classList.add("active");
      if (c.unread > 0) li.classList.add("has-unread");
      const emoji = roomEmojiFor(c.id);
      const peers = c.peerNames.size;
      const preview = lastPreview(c);
      const displayName =
        c.name || (peers > 0 ? "Активный чат" : "Пустой чат");
      li.innerHTML = `
        <span class="chat-avatar">${emoji}</span>
        <div class="chat-meta">
          <div class="chat-line1">
            <span class="chat-name">${escapeHtml(displayName)}</span>
            <span class="chat-peers" title="Кто сейчас в сети">${
              peers > 0 ? `${peers} 🤝` : "…"
            }</span>
          </div>
          <div class="chat-line2">
            <span class="chat-preview">${escapeHtml(preview)}</span>
            ${
              c.unread > 0
                ? `<span class="unread-badge">${c.unread}</span>`
                : ""
            }
          </div>
        </div>`;
      li.addEventListener("click", () => setActiveChat(c.id));
      list.appendChild(li);
    }
  }
  // self info
  $("me-nick").textContent = state.nick || "—";
  $("me-avatar").textContent = avatarFor(selfId);
}

function lastPreview(sess) {
  for (let i = sess.messages.length - 1; i >= 0; i--) {
    const m = sess.messages[i];
    if (m.kind === "text") return m.text;
    if (m.kind === "media") return "🎞️ медиа";
    if (m.kind === "sys") continue;
  }
  return "нет сообщений";
}

function lastActivity(sess) {
  if (!sess.messages?.length) return sess.createdAt || 0;
  return sess.messages[sess.messages.length - 1].ts || sess.createdAt || 0;
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// --- rendering: chat pane ---------------------------------------------------

function setActiveChat(id) {
  if (state.activeId && state.chats.has(state.activeId)) {
    // nothing to do on deactivation — session keeps running in background
  }
  state.activeId = id;
  if (id) {
    const sess = state.chats.get(id);
    if (sess) {
      sess.unread = 0;
      updateHashForActive(sess);
      renderChatPane(sess);
      $("empty-state").hidden = true;
      $("chat-pane").hidden = false;
      document.body.classList.add("chat-open");
    }
  } else {
    $("empty-state").hidden = false;
    $("chat-pane").hidden = true;
    document.body.classList.remove("chat-open");
    history.replaceState(null, "", location.pathname + location.search);
  }
  renderSidebar();
}

// Mirror the active chat's secret into URL fragment (handy for refresh).
function updateHashForActive(sess) {
  const target = `#${sess.secretStr}`;
  if (location.hash !== target) {
    history.replaceState(null, "", location.pathname + location.search + target);
  }
}

function renderChatIfActive(sess) {
  if (sess.id === state.activeId) renderChatPane(sess);
}

function renderChatPane(sess) {
  const emoji = roomEmojiFor(sess.id);
  $("room-emoji").textContent = emoji;
  $("chat-name").textContent = sess.name || "BRATAN-chat";
  updatePeerCount(sess);

  const list = $("messages");
  list.innerHTML = "";
  for (const m of sess.messages) {
    const node = renderMessageNode(sess, m);
    if (node) list.appendChild(node);
  }
  requestAnimationFrame(() => {
    scrollEl().scrollTop = scrollEl().scrollHeight;
    updateJumpDown();
  });
}

function renderMessageAppend(sess, m) {
  const list = $("messages");
  const node = renderMessageNode(sess, m);
  if (!node) return;
  const scroll = scrollEl();
  const wasAtBottom = isNearBottom(scroll);
  list.appendChild(node);
  if (wasAtBottom) {
    scroll.scrollTop = scroll.scrollHeight;
  } else if (m.kind !== "sys") {
    bumpJumpDown();
  }
  updateJumpDown();
}

function renderMessageNode(sess, m) {
  if (m.kind === "sys") {
    const li = document.createElement("li");
    li.className = "msg sys";
    const bubble = document.createElement("div");
    bubble.className = "bubble";
    bubble.textContent = m.text;
    li.append(bubble);
    return li;
  }
  const li = document.createElement("li");
  li.className = "msg" + (m.self ? " self" : "");

  const avatar = document.createElement("span");
  avatar.className = "avatar";
  avatar.textContent = avatarFor(m.from);

  const bubble = document.createElement("div");
  bubble.className = "bubble";

  const meta = document.createElement("div");
  meta.className = "meta";
  const user = document.createElement("span");
  user.className = "user";
  user.textContent = m.nick || (m.from ? m.from.slice(0, 6) : "братан");
  const time = document.createElement("span");
  time.textContent = " · " + fmtTime(m.ts);
  meta.append(user, time);
  bubble.append(meta);

  if (m.kind === "text") {
    const body = document.createElement("div");
    body.className = "text";
    body.textContent = m.text;
    bubble.append(body);
  } else if (m.kind === "media") {
    const img = document.createElement("img");
    img.className = "media";
    img.loading = "lazy";
    img.src = m.media.url;
    img.alt = "медиа";
    img.width = m.media.w;
    img.height = m.media.h;
    img.addEventListener("click", () => openLightbox(m.media.url));
    bubble.append(img);
    if (m.state === "sending") {
      const tag = document.createElement("div");
      tag.className = "media-tag";
      tag.textContent = "отправка…";
      bubble.append(tag);
    }
  }
  li.append(avatar, bubble);
  return li;
}

function updatePeerCount(sess) {
  const el = $("peer-count");
  const n = sess.peerNames.size;
  if (n === 0) {
    if (!sess.searchingSince) sess.searchingSince = Date.now();
    const secs = Math.floor((Date.now() - sess.searchingSince) / 1000);
    el.innerHTML = `<span class="searching"><span class="spinner">🔍</span> ищем братанов… ${secs}с</span>`;
  } else {
    sess.searchingSince = 0;
    el.textContent =
      n === 1 ? "1 братан на связи 🤝" : `${n} братанов на связи 🤝`;
  }
}

// Tick the "ищем…" counter on the active chat once a second.
setInterval(() => {
  const sess = state.activeId && state.chats.get(state.activeId);
  if (sess && sess.peerNames.size === 0) updatePeerCount(sess);
}, 1000);

// --- auto-scroll ------------------------------------------------------------

const scrollEl = () => $("messages-scroll");
const isNearBottom = (el) =>
  el.scrollHeight - el.scrollTop - el.clientHeight < 120;

function updateJumpDown() {
  const el = scrollEl();
  const btn = $("jump-down");
  if (isNearBottom(el)) {
    btn.hidden = true;
    btn.dataset.new = "0";
    $("jump-down-count").textContent = "внизу";
  } else if (btn.dataset.new && btn.dataset.new !== "0") {
    btn.hidden = false;
  }
}

function bumpJumpDown() {
  const btn = $("jump-down");
  const cur = Number(btn.dataset.new || "0") + 1;
  btn.dataset.new = String(cur);
  $("jump-down-count").textContent = `${cur} нов.`;
  btn.hidden = false;
}

function attachScrollHandlers() {
  const el = scrollEl();
  el.addEventListener("scroll", () => {
    if (isNearBottom(el)) {
      const btn = $("jump-down");
      btn.hidden = true;
      btn.dataset.new = "0";
    }
  });
  $("jump-down").addEventListener("click", () => {
    const el2 = scrollEl();
    el2.scrollTo({top: el2.scrollHeight, behavior: "smooth"});
    const btn = $("jump-down");
    btn.hidden = true;
    btn.dataset.new = "0";
  });
}

// --- media: encode to GIF ---------------------------------------------------

async function fileToBitmap(file) {
  if (typeof createImageBitmap === "function") {
    try {
      return await createImageBitmap(file);
    } catch {}
  }
  const url = URL.createObjectURL(file);
  try {
    const img = await new Promise((res, rej) => {
      const i = new Image();
      i.onload = () => res(i);
      i.onerror = rej;
      i.src = url;
    });
    return img;
  } finally {
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }
}

function fitSize(w, h, maxW) {
  if (w <= maxW) return {w, h};
  const scale = maxW / w;
  return {w: Math.round(w * scale), h: Math.round(h * scale)};
}

function makeCanvas(w, h) {
  if (typeof OffscreenCanvas === "function") return new OffscreenCanvas(w, h);
  const c = document.createElement("canvas");
  c.width = w;
  c.height = h;
  return c;
}

async function encodeImageToGif(file, onProgress) {
  const bitmap = await fileToBitmap(file);
  const {w, h} = fitSize(bitmap.width, bitmap.height, MEDIA_MAX_WIDTH);
  const canvas = makeCanvas(w, h);
  const ctx = canvas.getContext("2d", {willReadFrequently: true});
  ctx.drawImage(bitmap, 0, 0, w, h);
  if (typeof bitmap.close === "function") bitmap.close();
  const frame = ctx.getImageData(0, 0, w, h).data;

  const gif = GIFEncoder();
  const palette = quantize(frame, 256, {format: "rgba4444"});
  const index = applyPalette(frame, palette, "rgba4444");
  gif.writeFrame(index, w, h, {palette, delay: 0});
  gif.finish();
  onProgress?.(1);
  return {bytes: gif.bytes(), w, h, mime: "image/gif"};
}

async function encodeVideoToGif(file, onProgress, isCancelled) {
  const url = URL.createObjectURL(file);
  const video = document.createElement("video");
  video.muted = true;
  video.playsInline = true;
  video.preload = "auto";
  video.src = url;

  await new Promise((res, rej) => {
    video.onloadedmetadata = () => res();
    video.onerror = () => rej(new Error("не могу прочитать видео"));
  });

  const srcW = video.videoWidth;
  const srcH = video.videoHeight;
  if (!srcW || !srcH) throw new Error("видео без размеров");

  const {w, h} = fitSize(srcW, srcH, MEDIA_MAX_WIDTH);
  const duration = Math.min(video.duration || 0, MEDIA_MAX_DURATION_SEC);
  const frames = Math.max(2, Math.floor(duration * MEDIA_FPS));
  const frameDelay = Math.round(1000 / MEDIA_FPS);

  const canvas = makeCanvas(w, h);
  const ctx = canvas.getContext("2d", {willReadFrequently: true});
  const gif = GIFEncoder();

  for (let i = 0; i < frames; i++) {
    if (isCancelled?.()) throw new Error("отменено");
    const t = (i / (frames - 1)) * duration;
    await new Promise((res, rej) => {
      const handler = () => {
        video.removeEventListener("seeked", handler);
        res();
      };
      video.addEventListener("seeked", handler, {once: true});
      video.currentTime = Math.min(t, (video.duration || duration) - 0.001);
      setTimeout(() => {
        video.removeEventListener("seeked", handler);
        res();
      }, 1500);
    });
    ctx.drawImage(video, 0, 0, w, h);
    const data = ctx.getImageData(0, 0, w, h).data;
    const palette = quantize(data, 128, {format: "rgba4444"});
    const index = applyPalette(data, palette, "rgba4444");
    gif.writeFrame(index, w, h, {palette, delay: frameDelay});
    onProgress?.((i + 1) / frames);
    await new Promise((r) => setTimeout(r, 0));
  }

  gif.finish();
  URL.revokeObjectURL(url);
  return {bytes: gif.bytes(), w, h, mime: "image/gif"};
}

async function handleFilePick(file) {
  if (!file) return;
  if (file.size > MEDIA_MAX_INPUT_BYTES) {
    alert(`Файл слишком большой (${(file.size / 1024 / 1024).toFixed(1)} МБ). Максимум 50 МБ на входе, сожмётся до ~1-2 МБ в GIF.`);
    return;
  }
  const sess = state.activeId && state.chats.get(state.activeId);
  if (!sess) return;
  const isVideo = file.type.startsWith("video/");
  const progressEl = $("media-progress");
  const progressText = $("media-progress-text");
  const progressFill = $("progress-bar-fill");
  let cancelled = false;
  state.pendingMediaJob = {cancel: () => (cancelled = true)};
  progressEl.hidden = false;
  progressText.textContent = isVideo ? "Сжимаю видео в GIF…" : "Готовлю картинку…";
  progressFill.style.width = "0%";

  try {
    const result = isVideo
      ? await encodeVideoToGif(
          file,
          (p) => (progressFill.style.width = `${Math.round(p * 100)}%`),
          () => cancelled,
        )
      : await encodeImageToGif(file, (p) => {
          progressFill.style.width = `${Math.round(p * 100)}%`;
        });
    if (cancelled) return;
    if (result.bytes.length > 6 * 1024 * 1024) {
      if (!confirm(`GIF получился ${(result.bytes.length / 1024 / 1024).toFixed(1)} МБ. Всё равно отправить?`)) {
        return;
      }
    }
    progressText.textContent = "Шлю братанам…";
    progressFill.style.width = "0%";

    const mediaId = randomId();
    const blob = new Blob([result.bytes], {type: result.mime});
    const url = URL.createObjectURL(blob);
    sess.mediaBlobs.set(mediaId, url);
    const ts = Date.now();
    const ownMsg = {
      id: mediaId,
      from: selfId,
      nick: state.nick,
      ts,
      self: true,
      kind: "media",
      media: {url, mime: result.mime, w: result.w, h: result.h, size: result.bytes.length},
      state: "sending",
    };
    sess.messages.push(ownMsg);
    if (sess.id === state.activeId) renderMessageAppend(sess, ownMsg);
    renderSidebar();

    await sess.sendMedia(
      {
        mediaId,
        bytes: result.bytes,
        mime: result.mime,
        w: result.w,
        h: result.h,
        ts,
      },
      (percent) => {
        progressFill.style.width = `${Math.round(percent * 100)}%`;
      },
    );
    ownMsg.state = "sent";
    if (sess.id === state.activeId) renderChatPane(sess);
  } catch (err) {
    console.error(err);
    alert("Не вышло отправить медиа: " + err.message);
  } finally {
    progressEl.hidden = true;
    state.pendingMediaJob = null;
  }
}

// --- lightbox ---------------------------------------------------------------

function openLightbox(url) {
  $("lightbox-img").src = url;
  $("lightbox").hidden = false;
}
function closeLightbox() {
  $("lightbox").hidden = true;
  $("lightbox-img").src = "";
}

// --- modals -----------------------------------------------------------------

function openModal(id) {
  $(id).hidden = false;
}
function closeModal(id) {
  $(id).hidden = true;
}

// --- event wiring -----------------------------------------------------------

function wireEvents() {
  // Nick gate / settings
  $("nick-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const n = $("nick-input").value.trim().slice(0, 32);
    if (!n) return;
    state.nick = n;
    localStorage.setItem(NICK_KEY, n);
    $("nick-gate").hidden = true;
    await bootApp();
  });

  // Sidebar + new chat
  $("new-chat").addEventListener("click", () => openModal("new-chat-modal"));
  $("empty-new").addEventListener("click", () => {
    openModal("new-chat-modal");
    setTimeout(() => $("create").click(), 0);
  });
  $("empty-join").addEventListener("click", () => {
    openModal("new-chat-modal");
    setTimeout(() => $("join-input").focus(), 50);
  });

  $("create").addEventListener("click", async () => {
    closeModal("new-chat-modal");
    const {bytes, str} = generateSecret();
    const sess = await createChatFromSecret(str, bytes);
    setActiveChat(sess.id);
    $("invite-link").value = inviteUrl(str);
    openModal("invite-modal");
  });

  $("join-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const val = $("join-input").value;
    const parsed = parseInvite(val);
    if (!parsed) {
      alert("Эээ, это не похоже на ссылку-приглашение. Проверь, что вставил.");
      return;
    }
    $("join-input").value = "";
    closeModal("new-chat-modal");
    const sess = await createChatFromSecret(parsed.secret, parsed.bytes);
    setActiveChat(sess.id);
  });

  $("copy-invite").addEventListener("click", async () => {
    const val = $("invite-link").value;
    try {
      await navigator.clipboard.writeText(val);
    } catch {}
    const btn = $("copy-invite");
    const old = btn.innerHTML;
    btn.innerHTML = '<span class="btn-emoji">✅</span> Скопировано';
    setTimeout(() => (btn.innerHTML = old), 1500);
  });

  $("enter-room").addEventListener("click", () => closeModal("invite-modal"));

  // Chat header actions
  $("copy-invite-2").addEventListener("click", async () => {
    const sess = state.activeId && state.chats.get(state.activeId);
    if (!sess) return;
    try {
      await navigator.clipboard.writeText(inviteUrl(sess.secretStr));
    } catch {}
    const btn = $("copy-invite-2");
    const old = btn.textContent;
    btn.textContent = "✅";
    setTimeout(() => (btn.textContent = old), 1200);
  });

  $("rename-chat").addEventListener("click", () => {
    const sess = state.activeId && state.chats.get(state.activeId);
    if (!sess) return;
    $("rename-input").value = sess.name || "";
    openModal("rename-modal");
    setTimeout(() => $("rename-input").focus(), 50);
  });
  $("rename-form").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const sess = state.activeId && state.chats.get(state.activeId);
    if (!sess) return;
    sess.name = $("rename-input").value.trim().slice(0, 64);
    saveChatIndex();
    renderChatPane(sess);
    renderSidebar();
    closeModal("rename-modal");
  });

  $("leave-chat").addEventListener("click", () => {
    const sess = state.activeId && state.chats.get(state.activeId);
    if (!sess) return;
    if (
      !confirm(
        `Удалить чат "${sess.name || "без названия"}"? Секретный ключ тоже удалится — без ссылки обратно не попасть.`,
      )
    )
      return;
    removeChat(sess.id);
  });

  $("back").addEventListener("click", () => setActiveChat(null));

  // Composer
  $("composer").addEventListener("submit", (ev) => {
    ev.preventDefault();
    const sess = state.activeId && state.chats.get(state.activeId);
    if (!sess) return;
    const input = $("message-input");
    const text = input.value.trim();
    if (!text || !sess.sendMsg) return;
    const ts = Date.now();
    const msgId = randomId();
    sess.sendMsg({id: msgId, text, ts});
    const ownMsg = {
      id: msgId,
      from: selfId,
      nick: state.nick,
      ts,
      self: true,
      kind: "text",
      text,
    };
    sess.messages.push(ownMsg);
    renderMessageAppend(sess, ownMsg);
    renderSidebar();
    input.value = "";
  });

  $("attach").addEventListener("click", () => $("file-input").click());
  $("file-input").addEventListener("change", async (ev) => {
    const file = ev.target.files?.[0];
    ev.target.value = "";
    if (file) await handleFilePick(file);
  });
  $("media-cancel").addEventListener("click", () => {
    state.pendingMediaJob?.cancel();
  });

  // Settings
  $("settings").addEventListener("click", () => {
    $("settings-nick").value = state.nick;
    openModal("settings-modal");
  });
  $("save-nick").addEventListener("click", () => {
    const n = $("settings-nick").value.trim().slice(0, 32);
    if (!n) return;
    state.nick = n;
    localStorage.setItem(NICK_KEY, n);
    renderSidebar();
    // broadcast new nick to all sessions
    for (const sess of state.chats.values()) {
      for (const peerId of sess.peerNames.keys()) {
        try {
          sess.sendNick?.(n, peerId);
        } catch {}
      }
    }
    closeModal("settings-modal");
  });
  $("wipe-all").addEventListener("click", async () => {
    if (!confirm("Стереть все чаты, ключи и ник? Это неотменяемо.")) return;
    for (const sess of [...state.chats.values()]) {
      await stopSession(sess);
    }
    state.chats.clear();
    state.activeId = null;
    state.nick = "";
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(NICK_KEY);
    location.reload();
  });

  // Generic modal close
  document.addEventListener("click", (ev) => {
    const t = ev.target;
    if (!(t instanceof HTMLElement)) return;
    if (t.dataset.close !== undefined) {
      const layer = t.closest(".modal-layer, .lightbox");
      if (layer) layer.hidden = true;
    }
  });
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") {
      for (const id of [
        "new-chat-modal",
        "invite-modal",
        "rename-modal",
        "settings-modal",
      ]) {
        $(id).hidden = true;
      }
      if (!$("lightbox").hidden) closeLightbox();
    }
  });

  // Scroll handling
  attachScrollHandlers();
}

// --- bootstrap --------------------------------------------------------------

async function bootApp() {
  $("app").hidden = false;

  // Load saved chats
  const saved = loadChatIndex();
  for (const c of saved) {
    try {
      const bytes = b64urlDecode(c.secretStr);
      const [id, password] = await Promise.all([
        deriveRoomId(bytes),
        derivePassword(bytes),
      ]);
      const sess = createSession({
        id,
        secretStr: c.secretStr,
        secretBytes: bytes,
        password,
        name: c.name || "",
        createdAt: c.createdAt || Date.now(),
      });
      state.chats.set(id, sess);
    } catch (e) {
      console.warn("skip invalid saved chat", e);
    }
  }

  renderSidebar();

  // Start all sessions in background.
  await Promise.allSettled(
    [...state.chats.values()].map((s) => startSession(s)),
  );

  // Handle URL hash (deep-link)
  const parsed = parseInvite(location.hash);
  if (parsed) {
    const sess = await createChatFromSecret(parsed.secret, parsed.bytes);
    setActiveChat(sess.id);
  } else {
    setActiveChat(null);
  }
}

window.addEventListener("hashchange", async () => {
  const parsed = parseInvite(location.hash);
  if (!parsed) return;
  const sess = await createChatFromSecret(parsed.secret, parsed.bytes);
  setActiveChat(sess.id);
});

// Kick off
(async () => {
  wireEvents();
  if (!state.nick) {
    $("nick-gate").hidden = false;
    $("nick-input").value = "";
    $("nick-input").focus();
  } else {
    await bootApp();
  }
})();
