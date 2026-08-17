// keyjack — secure client.
//
// Read this file freely: it is served exactly as written, with no build step and no
// minification. Note what is NOT here — there is no key, no secret, no signing material,
// no client-side password hashing, and no client-minted pickup code. The client submits
// order *intent* only; the server re-derives price, restriction, authorization, the
// credential check, and the pickup code from state it holds.

const $ = (id) => document.getElementById(id);
let me = null;
let catalog = [];

async function api(path, options = {}) {
  const res = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
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

// UX-ONLY affordance. This mirrors the server's rule so the user gets an early hint, but
// it is a courtesy, never a control: the client sends none of this to the server, and the
// server recomputes the verdict from its own catalog and the actor's server-held limit.
function computeHint(part, quantity) {
  if (!part || !me || me.approval_limit_cents == null) return "";
  const lineTotal = part.unit_price_cents * quantity;
  const withinLimit = lineTotal <= me.approval_limit_cents;
  const requiresSupervisor = part.restricted || !withinLimit;
  if (requiresSupervisor) {
    return "⚠ This order will need supervisor approval before pickup.";
  }
  return "✓ This order is within your approval limit and will be auto-approved.";
}

function updateHint() {
  const part = catalog.find((p) => p.part_number === $("part-select").value);
  const qty = Math.max(1, parseInt($("quantity").value || "1", 10));
  $("order-hint").textContent = computeHint(part, qty);
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

  const cat = await api("/api/catalog");
  catalog = cat.body || [];
  $("part-select").innerHTML = catalog
    .map((p) => `<option value="${p.part_number}">${p.part_number} — ${p.name} · ` +
      `${money(p.unit_price_cents)}${p.restricted ? " · restricted" : ""}</option>`)
    .join("");

  const wos = await api("/api/work-orders");
  $("work-order-select").innerHTML = (wos.body || [])
    .map((w) => `<option value="${w.id}">${w.id} — ${w.description}</option>`)
    .join("");

  updateHint();
  await renderOrders();
  await renderMyPickups();

  const isSupervisor = me.role === "supervisor";
  $("supervisor-console").hidden = !isSupervisor;
  if (isSupervisor) await renderSupervisor();
}

// Show the server-issued pickup code for the signed-in owner's approved orders. The code
// comes from the server (order detail); the client never mints or guesses it.
async function renderMyPickups() {
  const res = await api("/api/orders");
  const mine = (res.body || []).filter(
    (o) => o.account_id === me.id &&
      (o.state === "approved" || o.state === "auto_approved"),
  );
  const details = await Promise.all(
    mine.map((o) => api(`/api/orders/${o.id}`).then((r) => r.body)),
  );
  $("my-pickups").innerHTML =
    details
      .map((o) => `<div class="pending-row"><span>${o.id} · ${o.part_number} · ` +
        `code <code class="pickup-code">${o.pickup_code}</code></span>` +
        `<button class="use-code" data-code="${o.pickup_code}">Use</button></div>`)
      .join("") || "<p>No approved orders awaiting pickup.</p>";
}

async function renderOrders() {
  const res = await api("/api/orders");
  const rows = (res.body || [])
    .map((o) => `<tr><td>${o.id}</td><td>${o.account_id}</td><td>${o.part_number}</td>` +
      `<td>${o.quantity}</td><td>${money(o.line_total_cents)}</td><td>${o.state}</td></tr>`)
    .join("");
  $("orders-table").querySelector("tbody").innerHTML = rows;
}

async function renderSupervisor() {
  const res = await api("/api/orders");
  const pending = (res.body || []).filter((o) => o.state === "pending_supervisor");
  $("pending-list").innerHTML = pending
    .map((o) => `<div class="pending-row" data-order="${o.id}">` +
      `<span>${o.id} · ${o.account_id} · ${o.part_number} · ${money(o.line_total_cents)}</span>` +
      `<button class="approve" data-order="${o.id}">Approve</button>` +
      `<button class="reject" data-order="${o.id}">Reject</button></div>`)
    .join("") || "<p>No pending orders.</p>";
}

function setMessage(text) {
  $("message").textContent = text;
}

document.addEventListener("DOMContentLoaded", () => {
  $("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    // The secure client posts the password itself; the server verifies it with a KDF.
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
    // Intent only: part, quantity, work order. No price, no verdict, no signature.
    const res = await api("/api/orders", {
      method: "POST",
      body: JSON.stringify({
        part_number: $("part-select").value,
        quantity: Math.max(1, parseInt($("quantity").value || "1", 10)),
        work_order_id: $("work-order-select").value,
      }),
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

  $("my-pickups").addEventListener("click", (e) => {
    const target = e.target;
    if (target instanceof HTMLElement && target.classList.contains("use-code")) {
      $("pickup-code").value = target.getAttribute("data-code") || "";
    }
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
