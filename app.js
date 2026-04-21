// BRATAN-chat: end-to-end encrypted P2P web chat.
//
// Architecture:
//   - A room is identified by a 32-byte random secret the user generates.
//   - The secret lives in the URL fragment (`#<base64url>`). Fragments are
//     never transmitted to any server, so the secret stays client-side.
//   - Two derived values:
//       * roomId = hex(SHA-256(secret || "bratan-chat/room/v1"))
//         -> this is what Trystero sends to public BitTorrent trackers for
//         discovery. Trackers learn the hash, not the secret.
//       * password = base64(SHA-256(secret || "bratan-chat/password/v1"))
//         -> passed to Trystero which derives an AES-GCM key from it via
//         PBKDF2 and encrypts every data-channel message with it. This is
//         an application-layer encryption layer *on top of* WebRTC's own
//         DTLS-SRTP encryption between peers.
//
// Threat model (honest):
//   - Anyone with the invite link (the fragment) can read and send messages
//     in the room. Treat the link like a password.
//   - Nicknames are self-reported — other peers in the room can claim any
//     nickname. Don't use nicknames to authenticate identities.
//   - Public BT trackers see peer IP addresses + the SHA-256-derived roomId.
//     They cannot read messages or learn the room secret.
//   - No history is stored anywhere. Close the tab and it's gone.

import {joinRoom, selfId} from "https://esm.sh/@trystero-p2p/torrent@0.23.1";

const APP_ID = "bratan-chat/v1";
const ROOM_SALT = "bratan-chat/room/v1";
const PASSWORD_SALT = "bratan-chat/password/v1";

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

// --- State ------------------------------------------------------------------

const state = {
  secret: null, // Uint8Array(32)
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
  const trimmed = text.trim();
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
  li.textContent = text;
  document.getElementById("messages").append(li);
  scrollToBottom();
}

function renderMessage({from, nick, text, ts, self}) {
  const li = document.createElement("li");
  li.className = "msg" + (self ? " self" : "");
  const meta = document.createElement("div");
  meta.className = "meta";
  const user = document.createElement("span");
  user.className = "user";
  user.textContent = nick || from.slice(0, 6);
  const time = document.createElement("span");
  time.textContent =
    " \u00b7 " +
    new Date(ts).toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
  meta.append(user, time);
  const body = document.createElement("div");
  body.className = "text";
  body.textContent = text;
  li.append(meta, body);
  document.getElementById("messages").append(li);
  scrollToBottom();
}

function scrollToBottom() {
  const main = document.querySelector("#chat main");
  if (main) main.scrollTop = main.scrollHeight;
}

function updatePeerCount() {
  const n = state.peerNames.size;
  const label = n === 0 ? "only you here" : n === 1 ? "1 peer connected" : `${n} peers connected`;
  document.getElementById("peer-count").textContent = label;
}

async function enterChat(secretStr, secretBytes) {
  state.secret = {str: secretStr, bytes: secretBytes};

  const [roomId, password] = await Promise.all([
    deriveRoomId(secretBytes),
    derivePassword(secretBytes),
  ]);

  const room = joinRoom({appId: APP_ID, password}, roomId);
  state.room = room;

  const [sendMsg, getMsg] = room.makeAction("msg");
  const [sendNick, getNick] = room.makeAction("nick");
  state.sendMsg = sendMsg;

  document.getElementById("messages").innerHTML = "";
  updatePeerCount();
  appendSystem(`joined as ${state.nick}`);

  room.onPeerJoin((peerId) => {
    state.peerNames.set(peerId, peerId.slice(0, 6));
    updatePeerCount();
    appendSystem(`${peerId.slice(0, 6)}\u2026 joined`);
    // Announce our nickname to the newcomer.
    sendNick(state.nick, peerId);
  });

  room.onPeerLeave((peerId) => {
    const name = state.peerNames.get(peerId) || peerId.slice(0, 6);
    state.peerNames.delete(peerId);
    updatePeerCount();
    appendSystem(`${name} left`);
  });

  getNick((nick, peerId) => {
    const clean = String(nick || "").slice(0, 32) || peerId.slice(0, 6);
    state.peerNames.set(peerId, clean);
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
  location.hash = "";
  show("landing");
}

// --- Event wiring -----------------------------------------------------------

document.getElementById("create").addEventListener("click", () => {
  const {str} = generateSecret();
  location.hash = str;
  document.getElementById("invite-link").value = inviteUrl(str);
  show("invite");
});

document.getElementById("join-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const val = document.getElementById("join-input").value;
  const parsed = parseInvite(val);
  if (!parsed) {
    alert("That doesn't look like a valid invite link.");
    return;
  }
  location.hash = parsed.secret;
  document.getElementById("join-input").value = "";
  routeFromHash();
});

document.getElementById("copy-invite").addEventListener("click", async () => {
  const val = document.getElementById("invite-link").value;
  try {
    await navigator.clipboard.writeText(val);
    const btn = document.getElementById("copy-invite");
    const old = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => (btn.textContent = old), 1500);
  } catch {
    document.getElementById("invite-link").select();
    document.execCommand("copy");
  }
});

document.getElementById("enter-room").addEventListener("click", () => {
  routeFromHash();
});

document.getElementById("back-to-landing").addEventListener("click", () => {
  location.hash = "";
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
  await enterChat(parsed.secret, parsed.bytes);
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
    const btn = document.getElementById("copy-invite-2");
    const old = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => (btn.textContent = old), 1500);
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
    document.getElementById("nick-input").value = state.nick || "";
    show("nick");
    document.getElementById("nick-input").focus();
    return;
  }
  enterChat(parsed.secret, parsed.bytes).catch((err) => {
    console.error(err);
    alert("Failed to join room: " + err.message);
    show("landing");
  });
}

// Pre-fill nickname if we remember one.
document.getElementById("nick-input").value = state.nick;

routeFromHash();
