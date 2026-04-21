// BRATAN-chat: E2EE P2P чат на GitHub Pages.
//
// Архитектура:
//   - Комната = 32-байтный случайный секрет, сгенерированный у тебя в браузере.
//   - Секрет лежит во фрагменте URL (`#<base64url>`). Фрагмент по RFC 3986
//     никогда не отправляется на сервер, так что секрет остаётся на клиенте.
//   - Из секрета выводятся два значения:
//       * roomId = hex(SHA-256(secret || "bratan-chat/room/v1"))
//         -> это то, что Trystero отправляет в публичные BitTorrent-трекеры
//         для обнаружения. Трекер видит хэш, не сам секрет.
//       * password = base64(SHA-256(secret || "bratan-chat/password/v1"))
//         -> передаётся в Trystero, тот выводит из него AES-GCM ключ через
//         PBKDF2 и шифрует каждое сообщение в data channel. Это
//         application-layer шифрование *поверх* родного DTLS-SRTP WebRTC
//         между пирами.
//
// Модель угроз (честно):
//   - У кого ссылка-приглашение (фрагмент) — тот может читать и писать в
//     комнату. Относись к ссылке как к паролю.
//   - Ники — самоназвания. Любой в комнате может представиться кем угодно.
//     Не аутентифицируй по нику.
//   - Публичные BT-трекеры видят IP пиров и SHA-256-производный roomId.
//     Они НЕ могут читать сообщения и не могут восстановить секрет.
//   - История нигде не хранится. Закрыл вкладку — чат исчез.

import {joinRoom, selfId} from "https://esm.sh/@trystero-p2p/torrent@0.23.1";

const APP_ID = "bratan-chat/v1";
const ROOM_SALT = "bratan-chat/room/v1";
const PASSWORD_SALT = "bratan-chat/password/v1";

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

const screens = {
  landing: document.getElementById("landing"),
  invite: document.getElementById("invite"),
  nick: document.getElementById("nick"),
  chat: document.getElementById("chat"),
};

function show(name) {
  for (const [key, el] of Object.entries(screens)) {
    el.hidden = key !== name;
  }
}

// --- URL-safe base64 helpers ------------------------------------------------

const b64urlEncode = (bytes) => {
  const str = btoa(String.fromCharCode(...bytes));
  return str.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
};
const b64urlDecode = (str) => {
  const pad = "=".repeat((4 - (str.length % 4)) % 4);
  const s = (str + pad).replaceAll("-", "+").replaceAll("_", "/");
  const bin = atob(s);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

const textEncoder = new TextEncoder();
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

async function deriveRoomId(secretBytes) {
  return toHex(await sha256(secretBytes, textEncoder.encode(ROOM_SALT)));
}
async function derivePassword(secretBytes) {
  return b64urlEncode(
    await sha256(secretBytes, textEncoder.encode(PASSWORD_SALT)),
  );
}

// --- Deterministic avatars --------------------------------------------------

function pickFromList(key, list) {
  let hash = 2166136261;
  for (let i = 0; i < key.length; i++) {
    hash ^= key.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return list[Math.abs(hash) % list.length];
}
const avatarFor = (peerId) => pickFromList(peerId || "self", AVATAR_EMOJI);
const roomEmojiFor = (roomId) => pickFromList(roomId, ROOM_EMOJI);

// --- State ------------------------------------------------------------------

const state = {
  secret: null, // {str, bytes}
  pendingSecret: null, // секрет только что созданной комнаты (до входа)
  room: null,
  sendMsg: null,
  nick: localStorage.getItem("bratan.nick") || "",
  peerNames: new Map(), // peerId -> nickname
};

// --- Room lifecycle ---------------------------------------------------------

function inviteUrl(secretStr) {
  const base = location.origin + location.pathname;
  return `${base}#${secretStr}`;
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

function generateSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const str = b64urlEncode(bytes);
  return {bytes, str};
}

function appendSystem(text) {
  const li = document.createElement("li");
  li.className = "msg sys";
  const bubble = document.createElement("div");
  bubble.className = "bubble";
  bubble.textContent = text;
  li.append(bubble);
  document.getElementById("messages").append(li);
  scrollToBottom();
}

function renderMessage({from, nick, text, ts, self}) {
  const li = document.createElement("li");
  li.className = "msg" + (self ? " self" : "");

  const avatar = document.createElement("span");
  avatar.className = "avatar";
  avatar.textContent = avatarFor(from);

  const bubble = document.createElement("div");
  bubble.className = "bubble";

  const meta = document.createElement("div");
  meta.className = "meta";
  const user = document.createElement("span");
  user.className = "user";
  user.textContent = nick || (from ? from.slice(0, 6) : "братан");
  const time = document.createElement("span");
  time.textContent =
    " · " +
    new Date(ts).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
  meta.append(user, time);

  const body = document.createElement("div");
  body.className = "text";
  body.textContent = text;

  bubble.append(meta, body);
  li.append(avatar, bubble);
  document.getElementById("messages").append(li);
  scrollToBottom();
}

function scrollToBottom() {
  const main = document.querySelector("#chat main");
  if (main) main.scrollTop = main.scrollHeight;
}

function updatePeerCount() {
  const n = state.peerNames.size;
  const label =
    n === 0
      ? "ты тут один 🙂"
      : n === 1
      ? "1 братан на связи 🤝"
      : `${n} братанов на связи 🤝`;
  document.getElementById("peer-count").textContent = label;
}

async function enterChat(secretStr, secretBytes) {
  state.secret = {str: secretStr, bytes: secretBytes};

  const [roomId, password] = await Promise.all([
    deriveRoomId(secretBytes),
    derivePassword(secretBytes),
  ]);

  document.getElementById("room-emoji").textContent = roomEmojiFor(roomId);

  const room = joinRoom({appId: APP_ID, password}, roomId);
  state.room = room;

  const [sendMsg, getMsg] = room.makeAction("msg");
  const [sendNick, getNick] = room.makeAction("nick");
  state.sendMsg = sendMsg;

  document.getElementById("messages").innerHTML = "";
  updatePeerCount();
  appendSystem(`зашёл как ${state.nick} ${avatarFor(selfId)}`);

  room.onPeerJoin((peerId) => {
    state.peerNames.set(peerId, peerId.slice(0, 6));
    updatePeerCount();
    appendSystem(`${avatarFor(peerId)} ${peerId.slice(0, 6)}… подключился 🤝`);
    sendNick(state.nick, peerId);
  });

  room.onPeerLeave((peerId) => {
    const name = state.peerNames.get(peerId) || peerId.slice(0, 6);
    state.peerNames.delete(peerId);
    updatePeerCount();
    appendSystem(`👋 ${name} вышел`);
  });

  getNick((nick, peerId) => {
    const clean = String(nick || "").slice(0, 32) || peerId.slice(0, 6);
    const prev = state.peerNames.get(peerId);
    state.peerNames.set(peerId, clean);
    if (prev && prev !== clean) {
      appendSystem(`${avatarFor(peerId)} ${prev} теперь ${clean}`);
    }
    updatePeerCount();
  });

  getMsg((payload, peerId) => {
    if (!payload || typeof payload !== "object") return;
    const text = String(payload.text || "").slice(0, 4000);
    const ts = Number(payload.ts) || Date.now();
    if (!text) return;
    const nick = state.peerNames.get(peerId) || peerId.slice(0, 6);
    renderMessage({from: peerId, nick, text, ts, self: false});
  });

  show("chat");
  document.getElementById("message-input").focus();
}

async function leaveChat() {
  if (state.room) {
    try {
      await state.room.leave();
    } catch {}
  }
  state.room = null;
  state.sendMsg = null;
  state.peerNames.clear();
  state.secret = null;
  state.pendingSecret = null;
  history.replaceState(null, "", location.pathname + location.search);
  show("landing");
}

async function flashCopy(btnId, okText) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  const old = btn.innerHTML;
  btn.classList.add("copied-flash");
  btn.innerHTML = `<span class="btn-emoji">✅</span> ${okText}`;
  setTimeout(() => {
    btn.classList.remove("copied-flash");
    btn.innerHTML = old;
  }, 1500);
}

// --- Event wiring -----------------------------------------------------------

document.getElementById("create").addEventListener("click", () => {
  const {str} = generateSecret();
  // Не ставим location.hash, чтобы не триггерить hashchange → routeFromHash,
  // который перекрыл бы invite-экран. Пушим фрагмент только при входе в чат.
  state.pendingSecret = str;
  document.getElementById("invite-link").value = inviteUrl(str);
  show("invite");
});

document.getElementById("join-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const val = document.getElementById("join-input").value;
  const parsed = parseInvite(val);
  if (!parsed) {
    alert("Эээ, это не похоже на ссылку-приглашение. Проверь, что вставил.");
    return;
  }
  document.getElementById("join-input").value = "";
  location.hash = parsed.secret;
});

document.getElementById("copy-invite").addEventListener("click", async () => {
  const val = document.getElementById("invite-link").value;
  try {
    await navigator.clipboard.writeText(val);
    flashCopy("copy-invite", "Скопировано");
  } catch {
    document.getElementById("invite-link").select();
    document.execCommand("copy");
    flashCopy("copy-invite", "Скопировано");
  }
});

document.getElementById("enter-room").addEventListener("click", () => {
  if (state.pendingSecret) {
    location.hash = state.pendingSecret;
    state.pendingSecret = null;
  } else {
    routeFromHash();
  }
});

document.getElementById("back-to-landing").addEventListener("click", () => {
  state.pendingSecret = null;
  history.replaceState(null, "", location.pathname + location.search);
  show("landing");
});

document.getElementById("nick-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const nick = document.getElementById("nick-input").value.trim().slice(0, 32);
  if (!nick) return;
  state.nick = nick;
  localStorage.setItem("bratan.nick", nick);
  const parsed = parseInvite(location.hash);
  if (!parsed) {
    show("landing");
    return;
  }
  try {
    await enterChat(parsed.secret, parsed.bytes);
  } catch (err) {
    console.error(err);
    alert("Не получилось зайти в комнату: " + err.message);
    show("landing");
  }
});

document.getElementById("composer").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const input = document.getElementById("message-input");
  const text = input.value.trim();
  if (!text || !state.sendMsg) return;
  const ts = Date.now();
  state.sendMsg({text, ts});
  renderMessage({from: selfId, nick: state.nick, text, ts, self: true});
  input.value = "";
});

document.getElementById("leave").addEventListener("click", leaveChat);

document.getElementById("copy-invite-2").addEventListener("click", async () => {
  if (!state.secret) return;
  const url = inviteUrl(state.secret.str);
  try {
    await navigator.clipboard.writeText(url);
    flashCopy("copy-invite-2", "Скопировано");
  } catch {}
});

window.addEventListener("hashchange", routeFromHash);

function routeFromHash() {
  const parsed = parseInvite(location.hash);
  if (!parsed) {
    show("landing");
    return;
  }
  if (!state.nick) {
    document.getElementById("nick-input").value = "";
    show("nick");
    document.getElementById("nick-input").focus();
    return;
  }
  enterChat(parsed.secret, parsed.bytes).catch((err) => {
    console.error(err);
    alert("Не получилось зайти в комнату: " + err.message);
    show("landing");
  });
}

// Pre-fill nickname if we remember one.
document.getElementById("nick-input").value = state.nick;

routeFromHash();
