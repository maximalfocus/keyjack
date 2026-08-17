// keyjack — VULNERABLE client (embedded signing key).
//
// This file is intentionally vulnerable local educational material. Read it: the flaw is in
// plain sight. The HMAC signing key below is a real, working key that this server verifies —
// and it is delivered to every browser that loads this page. "We sign our API requests"
// protects nothing when the signer's key is also the attacker's.
//
// The client here is honest (it signs the catalog's real prices). The point is that ANYONE
// holding this key — a browser devtools console, or the browserless attacker CLI — can sign
// a body full of false facts, and the server will trust it.

// >>> The shipped secret. This is the whole vulnerability. <<<
const SIGNING_KEY = "ninebark-demo-signing-key-DO-NOT-REUSE-0000000000";

const $ = (id) => document.getElementById(id);
let me = null;
let catalog = [];

async function api(path, options = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const body = res.headers.get("content-type")?.includes("application/json")
    ? await res.json()
    : null;
  return { ok: res.ok, status: res.status, body };
}

function money(cents) {
  return "$" + (cents / 100).toFixed(2);
}

// The canonical serialization the server recomputes and verifies. Must match the server.
function canonicalOrder(o) {
  return [
    `part_number=${o.part_number}`,
    `quantity=${o.quantity}`,
    `work_order_id=${o.work_order_id}`,
    `unit_price_cents=${o.unit_price_cents}`,
    `restricted=${o.restricted ? "true" : "false"}`,
    `line_total_cents=${o.line_total_cents}`,
  ].join("\n");
}

// HMAC-SHA256 with the embedded key, via WebCrypto. Conventional, correct — and pointless
// as a control, because the key is right here in the page.
async function sign(message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(SIGNING_KEY), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function updateHint() {
  const part = catalog.find((p) => p.part_number === $("part-select").value);
  const qty = Math.max(1, parseInt($("quantity").value || "1", 10));
  if (!part || !me || me.approval_limit_cents == null) {
    $("order-hint").textContent = "";
    return;
  }
  const lineTotal = part.unit_price_cents * qty;
  const requires = part.restricted || lineTotal > me.approval_limit_cents;
  $("order-hint").textContent = requires
    ? "⚠ This order will need supervisor approval before pickup."
    : "✓ This order is within your approval limit and will be auto-approved.";
}

async function refresh() {
  const meRes = await api("/api/me");
  if (!meRes.ok) {
    me = null;
    $("login-view").hidden = false;
    $("app-view").hidden = true;
    return;
  }
  me = meRes.body;
  $("login-view").hidden = true;
  $("app-view").hidden = false;
  $("whoami").textContent =
    `Signed in as ${me.display_name} (${me.id})` +
    (me.approval_limit_cents != null ? ` · limit ${money(me.approval_limit_cents)}` : "");

  catalog = (await api("/api/catalog")).body || [];
  $("part-select").innerHTML = catalog
    .map((p) => `<option value="${p.part_number}">${p.part_number} — ${p.name} · ` +
      `${money(p.unit_price_cents)}${p.restricted ? " · restricted" : ""}</option>`)
    .join("");
  $("work-order-select").innerHTML = ((await api("/api/work-orders")).body || [])
    .map((w) => `<option value="${w.id}">${w.id} — ${w.description}</option>`)
    .join("");

  updateHint();
  await renderOrders();
  await renderMyPickups();

  const isSupervisor = me.role === "supervisor";
  $("supervisor-console").hidden = !isSupervisor;
  if (isSupervisor) await renderSupervisor();
}

async function renderOrders() {
  const rows = ((await api("/api/orders")).body || [])
    .map((o) => `<tr><td>${o.id}</td><td>${o.account_id}</td><td>${o.part_number}</td>` +
      `<td>${o.quantity}</td><td>${money(o.line_total_cents)}</td><td>${o.state}</td></tr>`)
    .join("");
  $("orders-table").querySelector("tbody").innerHTML = rows;
}

async function renderSupervisor() {
  const pending = ((await api("/api/orders")).body || [])
    .filter((o) => o.state === "pending_supervisor");
  $("pending-list").innerHTML = pending
    .map((o) => `<div class="pending-row" data-order="${o.id}">` +
      `<span>${o.id} · ${o.account_id} · ${o.part_number} · ${money(o.line_total_cents)}</span>` +
      `<button class="approve" data-order="${o.id}">Approve</button>` +
      `<button class="reject" data-order="${o.id}">Reject</button></div>`)
    .join("") || "<p>No pending orders.</p>";
}

async function renderMyPickups() {
  const mine = ((await api("/api/orders")).body || []).filter(
    (o) => o.account_id === me.id &&
      (o.state === "approved" || o.state === "auto_approved"),
  );
  const details = await Promise.all(
    mine.map((o) => api(`/api/orders/${o.id}`).then((r) => r.body)),
  );
  $("my-pickups").innerHTML =
    details
      .map((o) => `<div class="pending-row"><span>${o.id} · ${o.part_number} · ` +
        `code <code class="pickup-code">${o.pickup_code}</code></span></div>`)
      .join("") || "<p>No approved orders awaiting pickup.</p>";
}

function setMessage(text) {
  $("message").textContent = text;
}

document.addEventListener("DOMContentLoaded", () => {
  $("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const res = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        account_id: $("account-id").value,
        password: $("password").value,
      }),
    });
    setMessage(res.ok ? "" : "Sign-in failed.");
    if (res.ok) await refresh();
  });

  $("logout-btn").addEventListener("click", async () => {
    await api("/api/logout", { method: "POST" });
    await refresh();
  });

  $("part-select").addEventListener("change", updateHint);
  $("quantity").addEventListener("input", updateHint);

  $("order-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const part = catalog.find((p) => p.part_number === $("part-select").value);
    const qty = Math.max(1, parseInt($("quantity").value || "1", 10));
    // The client signs the catalog's real facts. The signature is honest here; the flaw is
    // that the *key* to make one is public, so a forger can sign false facts just as well.
    const order = {
      part_number: part.part_number,
      quantity: qty,
      work_order_id: $("work-order-select").value,
      unit_price_cents: part.unit_price_cents,
      restricted: part.restricted,
      line_total_cents: part.unit_price_cents * qty,
    };
    const signature = await sign(canonicalOrder(order));
    const res = await api("/api/orders", {
      method: "POST",
      headers: { "X-Ninebark-Signature": signature },
      body: JSON.stringify(order),
    });
    setMessage(res.ok ? `Order ${res.body.id}: ${res.body.state}` : "Order refused.");
    await renderOrders();
    if (me && me.role === "supervisor") await renderSupervisor();
  });

  $("pending-list").addEventListener("click", async (e) => {
    const target = e.target;
    if (!(target instanceof HTMLElement)) return;
    const orderId = target.getAttribute("data-order");
    if (!orderId) return;
    if (target.classList.contains("approve")) {
      await api(`/api/orders/${orderId}/approve`, { method: "POST" });
    } else if (target.classList.contains("reject")) {
      await api(`/api/orders/${orderId}/reject`, { method: "POST" });
    }
    await renderOrders();
    await renderSupervisor();
  });

  $("pickup-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const res = await api("/api/pickup", {
      method: "POST",
      body: JSON.stringify({ code: $("pickup-code").value }),
    });
    setMessage(res.ok ? `Collected ${res.body.id}.` : "Pickup refused.");
    await renderOrders();
    await renderMyPickups();
  });

  refresh();
});
