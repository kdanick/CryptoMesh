const API = "http://localhost:5000/api";

let me = null;
let myPass = null;
let activePeer = null;
let sessionMessages = []; // this session's message history — sessionStorage-backed
let inspectorOpen = true;

// ===== Notification System =====
let knownMessages = new Set();
let unreadCounts = {};
let pollingStarted = false;

// ===============================

const colors = [
  "#3b82f6",
  "#22c55e",
  "#a78bfa",
  "#f59e0b",
  "#ef4444",
  "#06b6d4",
  "#f97316",
];
function avatarColor(name) {
  let h = 0;
  for (let c of name) h = (h * 31 + c.charCodeAt(0)) % colors.length;
  return colors[h];
}

function initials(name) {
  return name.slice(0, 2).toUpperCase();
}

function timeStr() {
  return new Date().toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
  });
}

// ===============================
// sessionMessages persistence helpers
// ===============================

function loadSessionMessages() {
  try {
    const raw = sessionStorage.getItem("cm_messages");
    sessionMessages = raw ? JSON.parse(raw) : [];
  } catch (e) {
    sessionMessages = [];
  }
}

function saveSessionMessages() {
  sessionStorage.setItem("cm_messages", JSON.stringify(sessionMessages));
}

// ===============================
// Session Check
// ===============================

(function () {
  const u = sessionStorage.getItem("cm_user");
  const p = sessionStorage.getItem("cm_pass");

  if (!u || !p) {
    window.location.href = "/login";
    return;
  }

  me = u;
  myPass = p;

  loadSessionMessages(); // restore history from this browser session (survives refresh)

  document.getElementById("user-badge").textContent = "● " + me;

  loadContacts();
  fetchMessages();

  if (!pollingStarted) {
    pollingStarted = true;
    setInterval(pollMessages, 2000);
  }
})();

// ===============================
// Logout
// ===============================

function doLogout() {
  sessionStorage.removeItem("cm_user");
  sessionStorage.removeItem("cm_pass");
  sessionStorage.removeItem("cm_messages"); // wipe history — this is the "forget everything" point

  sessionMessages = [];
  knownMessages.clear();
  unreadCounts = {};

  window.location.href = "/login";
}

// ===============================
// Register
// ===============================

function openRegModal() {
  window.location.href = "/register";
}

function closeRegModal() {}

// ===============================
// Contacts
// ===============================

async function loadContacts() {
  try {
    const r = await fetch(`${API}/users`);
    const d = await r.json();

    const list = document.getElementById("user-list");
    list.innerHTML = "";

    d.users
      .filter((u) => u !== me)
      .forEach((u) => {
        const unread = unreadCounts[u] || 0;
        const item = document.createElement("div");
        item.className = "user-item" + (u === activePeer ? " active" : "");
        item.innerHTML = `
          <div class="avatar"
          style="background:${avatarColor(u)}22;color:${avatarColor(u)}">
            ${initials(u)}
          </div>
          <div style="flex:1">
            <div class="uname">${u}</div>
            <div class="ustatus">
              🔒 end-to-end encrypted
            </div>
          </div>
          ${unread > 0 ? `<div class="unread-badge">${unread}</div>` : ""}
        `;
        item.onclick = () => openChat(u);
        list.appendChild(item);
      });
  } catch (e) {
    console.log(e);
  }
}

// ===============================
// Open Chat
// ===============================

async function openChat(peer) {
  activePeer = peer;
  unreadCounts[peer] = 0;

  document.getElementById("chat-title").textContent = peer;
  document.getElementById("compose-input").disabled = false;
  document.getElementById("btn-send").disabled = false;
  document.getElementById("compose-input").focus();

  loadContacts();
  renderMessages();
  await fetchMessages();
}

// ===============================
// Fetch Messages (server DELETES each file as it delivers it)
// ===============================

async function fetchMessages() {
  if (!me || !myPass) return;

  try {
    const r = await fetch(`${API}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: me, password: myPass }),
    });

    const d = await r.json();
    if (!r.ok) return;

    let changed = false;

    (d.messages || []).forEach((msg) => {
      if (!knownMessages.has(msg.filename)) {
        knownMessages.add(msg.filename);
        sessionMessages.push(msg);
        changed = true;
      }
    });

    if (changed) {
      saveSessionMessages();
      renderMessages();
    }
  } catch (e) {
    console.log(e);
  }
}

// ===============================
// Render Messages
// ===============================

function renderMessages() {
  const box = document.getElementById("messages");

  const convo = sessionMessages.filter(
    (m) => m.sender === activePeer || m.recipient === activePeer,
  );

  const all = [...convo].sort(
    (a, b) => (a.timestamp || 0) - (b.timestamp || 0),
  );

  if (all.length === 0) {
    box.innerHTML = `
      <div class="empty-chat">
        <div class="icon">💬</div>
        <p>No messages yet — say something!</p>
      </div>
    `;
    return;
  }

  box.innerHTML = "";

  all.forEach((msg, i) => {
    const sent = msg.sender === me;
    const row = document.createElement("div");
    row.className = "msg-row " + (sent ? "sent" : "received");
    const color = avatarColor(msg.sender);

    const sigBadge =
      msg.sig_valid === true
        ? `<span class="sig-ok">✓ signed</span>`
        : msg.sig_valid === false
          ? `<span class="sig-bad">✗ bad sig</span>`
          : "";

    row.innerHTML = `
      <div class="bubble-avatar"
      style="background:${color}22;color:${color}">
        ${initials(msg.sender)}
      </div>
      <div class="bubble-wrap">
        <div class="bubble"
             onclick="inspectMessage(${i},'${sent ? "sent" : "recv"}')">
          ${msg.plaintext || "<em style='color:var(--text3)'>encrypted</em>"}
        </div>
        <div class="bubble-meta">
        <span class="bubble-time">
          ${
            msg.timestamp
              ? new Date(msg.timestamp).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                })
              : "--:--"
          }
        </span>
          ${sigBadge}
          <span class="crypto-hint">
            AES-256-GCM
          </span>
        </div>
      </div>
    `;

    row.dataset.idx = i;
    box.appendChild(row);
  });

  box.scrollTop = box.scrollHeight;
  window._allRendered = all;
}

// ===============================
// Send Message
// ===============================

async function doSend() {
  if (!me || !activePeer) return;

  const ta = document.getElementById("compose-input");
  const msg = ta.value.trim();
  if (!msg) return;

  ta.value = "";
  ta.style.height = "auto";

  try {
    const r = await fetch(`${API}/send`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        sender: me,
        password: myPass,
        recipient: activePeer,
        message: msg,
      }),
    });

    const d = await r.json();
    if (!r.ok) return alert(d.error || "Send failed");

    // The server never stores or returns our own plaintext (forward
    // secrecy) — so we record what we sent directly into session history.
    sessionMessages.push({
      filename: `local_${Date.now()}`,
      sender: me,
      recipient: activePeer,
      timestamp: Date.now(),
      plaintext: msg,
      sig_valid: true,
      steps: d.steps,
    });
    saveSessionMessages();

    renderMessages();
    showInspector(d.steps, msg, "sent");
  } catch (e) {
    alert("Backend unreachable");
  }
}

// ===============================
// Poll Server Every 2 Seconds
// ===============================

async function pollMessages() {
  if (!me || !myPass) return;

  try {
    const r = await fetch(`${API}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: me, password: myPass }),
    });

    const d = await r.json();
    if (!r.ok) return;

    let changed = false;

    (d.messages || []).forEach((msg) => {
      if (!knownMessages.has(msg.filename)) {
        knownMessages.add(msg.filename);
        sessionMessages.push(msg);
        changed = true;

        if (msg.sender !== me && msg.sender !== activePeer) {
          unreadCounts[msg.sender] = (unreadCounts[msg.sender] || 0) + 1;
          showBrowserNotification(msg.sender);
        }
      }
    });

    if (changed) {
      saveSessionMessages();
      renderMessages();
      loadContacts();
    }
  } catch (e) {
    console.log(e);
  }
}

// ===============================
// Browser Notifications
// ===============================

if ("Notification" in window) {
  Notification.requestPermission();
}

function showBrowserNotification(sender) {
  if (Notification.permission === "granted") {
    new Notification("CryptoMesh", {
      body: `New encrypted message from ${sender}`,
      icon: "/static/icon.png",
    });
  }
}

// ── inspector ──
function toggleInspector() {
  inspectorOpen = !inspectorOpen;
  document
    .getElementById("inspector")
    .classList.toggle("hidden", !inspectorOpen);
}

function inspectMessage(idx, dir) {
  const all = window._allRendered || [];
  const msg = all[idx];
  if (!msg) return;
  if (!inspectorOpen) {
    inspectorOpen = true;
    document.getElementById("inspector").classList.remove("hidden");
  }
  showInspector(msg.steps, msg.plaintext, dir, msg);
}

const stepClasses = {
  Unlock: "auth",
  "Diffie-Hellman": "dh",
  "Station-to-Station": "dh",
  "Key Derivation": "kdf",
  "SHA-256": "kdf",
  AES: "enc",
  Encryption: "enc",
  Decryption: "enc",
  GCM: "enc",
  RSA: "sig",
  "RSA-PSS": "sig",
  Signature: "sig",
  Verify: "sig",
  Saved: "save",
  disk: "save",
  discarded: "save",
};

function stepClass(name) {
  for (const [k, v] of Object.entries(stepClasses))
    if (name.includes(k)) return v;
  return "";
}

function showInspector(steps, plaintext, dir, msg) {
  const body = document.getElementById("inspector-body");
  const dirLabel = dir === "sent" ? "↑ outgoing" : "↓ incoming";
  const dirColor = dir === "sent" ? "var(--accent)" : "var(--green)";

  let html = `
    <div class="insp-section">
      <div class="insp-label">Message</div>
      <div class="algo-badge" style="border-color:${dirColor};color:var(--text)">${dirLabel} — "${plaintext || "(encrypted)"}"</div>
    </div>
    <div class="insp-section">
      <div class="insp-label">Protocol</div>
  <div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px">
    <span class="tag tag-dh">DH 2048-bit MODP</span>
    <span class="tag tag-kdf">SHA-256 KDF</span>
    <span class="tag tag-enc">AES-256-GCM</span>
    <span class="tag tag-sig">RSA-PSS</span>
  </div>
    </div>
    <div class="insp-section">
      <div class="insp-label">Operations (${(steps || []).length} steps)</div>
  `;

  (steps || []).forEach((s, i) => {
    const cls = stepClass(s.step);
    html += `<div class="step-item ${cls}" style="animation-delay:${i * 60}ms">
      <div class="step-name">${s.step}</div>
      <div class="step-detail">${s.detail}</div>
    </div>`;
  });

  if (!steps || steps.length === 0) {
    html +=
      '<div style="color:var(--text3);font-size:0.78rem">No step data available for this message.</div>';
  }

  html += "</div>";

  if (msg && msg.sig_valid !== undefined) {
    html += `<div class="insp-section">
      <div class="insp-label">Integrity</div>
      <div class="algo-badge" style="border-color:${msg.sig_valid ? "var(--green)" : "var(--red)"}">
        RSA-PSS signature: ${msg.sig_valid ? "✓ VALID — sender authenticated" : "✗ INVALID — possible forgery"}
      </div>
    </div>`;
  }

  body.innerHTML = html;
}
