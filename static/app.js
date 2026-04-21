(() => {
  const msgs = document.getElementById("messages");
  const form = document.getElementById("composer");
  const input = document.getElementById("input");
  const meEl = document.getElementById("me");

  let me = { user: "", login: "" };
  let ws = null;
  let reconnectDelay = 500;

  const fmtTime = (iso) => {
    try {
      return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    } catch {
      return "";
    }
  };

  const renderMessage = (m) => {
    const li = document.createElement("li");
    li.className = "msg" + (m.login && m.login === me.login ? " self" : "");
    const meta = document.createElement("div");
    meta.className = "meta";
    const user = document.createElement("span");
    user.className = "user";
    user.textContent = m.user || m.login || "unknown";
    const time = document.createElement("span");
    time.textContent = " \u00b7 " + fmtTime(m.ts);
    meta.append(user, time);
    const text = document.createElement("div");
    text.className = "text";
    text.textContent = m.text;
    li.append(meta, text);
    msgs.append(li);
    msgs.parentElement.scrollTop = msgs.parentElement.scrollHeight;
  };

  const connect = () => {
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    ws = new WebSocket(`${proto}//${location.host}/ws`);
    ws.addEventListener("open", () => {
      reconnectDelay = 500;
    });
    ws.addEventListener("message", (ev) => {
      try {
        renderMessage(JSON.parse(ev.data));
      } catch (err) {
        console.error("bad message", err, ev.data);
      }
    });
    ws.addEventListener("close", () => {
      setTimeout(connect, reconnectDelay);
      reconnectDelay = Math.min(reconnectDelay * 2, 10_000);
    });
  };

  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    const text = input.value.trim();
    if (!text || !ws || ws.readyState !== WebSocket.OPEN) return;
    ws.send(JSON.stringify({ text }));
    input.value = "";
  });

  fetch("/api/whoami")
    .then((r) => r.json())
    .then((who) => {
      me = who;
      meEl.textContent = who.user ? `signed in as ${who.user}` : "signed in";
      connect();
    })
    .catch((err) => {
      meEl.textContent = "identity lookup failed";
      console.error(err);
    });
})();
