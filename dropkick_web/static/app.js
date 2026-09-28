// Shared by every page: header, API calls, form persistence, formatting.

const PAGES = [
  ["index.html", "Chain"],
  ["fund.html", "Outputs"],
  ["commit.html", "Commit"],
  ["reveal.html", "Reveal"],
  ["tx.html", "Transaction"],
];

const KIND_LABELS = {
  p2pkh: "P2PKH", p2wpkh: "P2WPKH", p2sh_p2wpkh: "P2SH-P2WPKH", p2sh: "P2SH", p2wsh: "P2WSH",
};
const WIT_LABELS = { 1: "0x01 pubkey", 2: "0x02 xprv", 3: "0x03 script" };
const OUT_LABELS = { 1: "P2PKH", 2: "P2WPKH", 3: "P2SH-P2WPKH", 4: "P2SH", 5: "P2WSH" };
const STATUS_BADGE = {
  defined: "", started: "warn", locked_in: "warn", active: "bad",
  funded: "info", committed: "warn", spent: "",
};

const DK = { state: null };

async function api(path, body) {
  const opts = body === undefined ? {} : { method: "POST", body: JSON.stringify(body) };
  const res = await fetch("/api/" + path, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

async function loadState() {
  DK.state = await api("state");
  renderChainBadge();
  return DK.state;
}

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v === true) node.setAttribute(k, "");
    else node.setAttribute(k, v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

function hex(value, keep = 8) {
  if (!value) return el("span", { class: "empty" }, "—");
  const text = value.length > keep * 2 + 1 ? value.slice(0, keep) + "…" + value.slice(-keep) : value;
  return el("span", {
    class: "hex", title: value + "\n(click to copy)",
    onclick: () => copyText(value),
  }, text);
}

function txLink(txid, keep = 8) {
  if (!txid) return el("span", { class: "empty" }, "—");
  const text = txid.slice(0, keep) + "…" + txid.slice(-keep);
  return el("a", { class: "hex", href: "tx.html?txid=" + txid, title: txid + "\n(open transaction)" }, text);
}

function copyText(text) {
  navigator.clipboard?.writeText(text).then(() => toast("Copied"), () => {});
}

function badge(text, kind) {
  return el("span", { class: "badge " + (kind ?? STATUS_BADGE[text] ?? "") }, text);
}

function sats(n) {
  return Number(n).toLocaleString("en-US") + " sat";
}

function progress(depth, need) {
  const done = depth >= need;
  const pct = Math.max(0, Math.min(100, (depth / need) * 100));
  return el("div", { class: "depth", title: `depth ${depth} of ${need} required` },
    el("div", { class: "progress" + (done ? " done" : "") }, el("div", { style: `width:${pct}%` })),
    el("span", { class: "hint" }, done ? "buried" : `${Math.max(depth, 0)}/${need}`));
}

let toastTimer;
function toast(msg) {
  let t = document.getElementById("toast");
  if (!t) { t = el("div", { id: "toast" }); document.body.append(t); }
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 2500);
}

// Run an action with its button disabled; a button the page turned off (setOff) stays off.
async function busy(button, label, fn) {
  const saved = button.textContent;
  button.disabled = true;
  button.classList.add("busy");
  button.textContent = label;
  try {
    return await fn();
  } catch (e) {
    toast("Error: " + e.message);
  } finally {
    button.disabled = button.dataset.off === "1";
    button.classList.remove("busy");
    button.textContent = saved;
  }
}

function setOff(button, off) {
  button.dataset.off = off ? "1" : "";
  button.disabled = off;
}

// Re-read the state when the tab comes back into view, so a page left open does not go stale.
function watchState(render) {
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible") loadState().then(render).catch(() => {});
  });
}

function resultBox(ok, title, detail, kind) {
  return el("div", { class: "result " + (kind ?? (ok ? "ok" : "bad")) },
    el("div", { class: "title" }, title),
    detail ? el("pre", {}, detail) : null);
}

function kv(rows) {
  return el("table", {}, rows.map(([k, v]) => el("tr", {}, el("th", { style: "width:180px" }, k), el("td", {}, v))));
}

function payloadTables(p) {
  return el("div", { class: "table-wrap" },
    el("table", {},
      el("tr", {}, ["Anchor", "Block", "tx_index", "tx_depth", "tx_len"].map(h => el("th", {}, h))),
      p.anchors.map((a, i) => el("tr", {}, el("td", {}, i), el("td", {}, hex(a.block_hash)),
        el("td", {}, a.tx_index), el("td", {}, a.tx_depth), el("td", {}, a.tx_len)))),
    p.salvagers.length ? el("table", { style: "margin-top:10px" },
      el("tr", {}, ["Salvager", "spk"].map(h => el("th", {}, h))),
      p.salvagers.map((s, i) => el("tr", {}, el("td", {}, i), el("td", {}, hex(s, 12))))) : null,
    el("table", { style: "margin-top:10px" },
      el("tr", {}, ["Witness", "anchor_idx", "sv_idx", "sv_sat", "leaf", "wit_type", "wit_data"].map(h => el("th", {}, h))),
      p.witnesses.map((w, i) => el("tr", {}, el("td", {}, i), el("td", {}, w.anchor_idx), el("td", {}, w.sv_idx),
        el("td", {}, w.sv_sat), el("td", {}, w.leaf_index), el("td", {}, WIT_LABELS[w.wit_type]),
        el("td", {}, hex(w.wit_data))))),
    el("table", { style: "margin-top:10px" },
      el("tr", {}, ["Claim", "input_idx", "wit_idx", "out_type", "path"].map(h => el("th", {}, h))),
      p.claims.map((c, i) => el("tr", {}, el("td", {}, i), el("td", {}, c.input_idx), el("td", {}, c.wit_idx),
        el("td", {}, OUT_LABELS[c.out_type]), el("td", {}, c.path)))));
}

// --- header --------------------------------------------------------------

function renderHeader() {
  const page = location.pathname.split("/").pop() || "index.html";
  const header = el("header", {},
    el("span", { class: "brand" }, "DropKick sandbox"),
    el("nav", {}, PAGES.map(([href, name]) =>
      el("a", { href, class: href === page ? "active" : null }, name))),
    el("div", { class: "chain", id: "chain-badge" }));
  document.body.prepend(header);
}

function renderChainBadge() {
  const box = document.getElementById("chain-badge");
  if (!box || !DK.state) return;
  const s = DK.state.status;
  box.replaceChildren(
    el("span", {}, "height ", el("b", {}, s.height)),
    badge("dropkick: " + s.dropkick, STATUS_BADGE[s.dropkick]));
}

// --- form persistence ------------------------------------------------------
//
// Inputs marked data-persist keep their value across page switches. Storage
// can be unavailable (private mode); the page then simply starts blank.

function persistKey(input) {
  const page = location.pathname.split("/").pop() || "index.html";
  return `dk:${page}:${input.name || input.id}`;
}

function restoreForm(root = document) {
  for (const input of root.querySelectorAll("[data-persist]")) {
    let saved = null;
    try { saved = localStorage.getItem(persistKey(input)); } catch (e) { /* no storage */ }
    if (saved !== null) {
      if (input.type === "radio") input.checked = input.value === saved;
      else if (input.type === "checkbox") input.checked = saved === "1";
      else input.value = saved;
    }
    input.addEventListener("change", () => saveInput(input));
    input.addEventListener("input", () => saveInput(input));
  }
}

function saveInput(input) {
  if (input.type === "radio" && !input.checked) return;
  const value = input.type === "checkbox" ? (input.checked ? "1" : "0") : input.value;
  try { localStorage.setItem(persistKey(input), value); } catch (e) { /* no storage */ }
}

function formValue(name) {
  const inputs = document.querySelectorAll(`[name="${name}"]`);
  for (const input of inputs) {
    if (input.type === "radio") { if (input.checked) return input.value; continue; }
    if (input.type === "checkbox") return input.checked;
    return input.value.trim();
  }
  return "";
}

function keyDescription(u) {
  const k = u.key;
  if (k.type === "script") return "script";
  if (k.type === "xprv") return "xprv " + (DK.state.paths[u.id] || "");
  return k.compressed ? "key" : "key (uncompressed)";
}

function utxoLabel(u) {
  return `${u.id} · ${KIND_LABELS[u.kind]} · ${keyDescription(u)} · ${sats(u.amount)}`;
}

renderHeader();
