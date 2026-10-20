// Tunnelik's UI. Talks to the Rust side through Tauri commands (src/main.rs).
//
// Browsing tunnels shows an overview built from `tunnel_details`, which never contains private
// or preshared keys. The full config, private key included, is only loaded into the editor when
// the user asks to edit, and cleared again when the editor closes.
const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);
const ui = {
  list: $("tunnels"), add: $("new"), empty: $("empty"),
  details: $("details"), dName: $("d-name"), dInterface: $("d-interface"), dPeers: $("d-peers"),
  toggle: $("toggle"), edit: $("edit"), del: $("delete"),
  editor: $("editor"), name: $("name"), config: $("config"), check: $("check"),
  importFile: $("import"), cancel: $("cancel"), save: $("save"), error: $("error"),
};

let tunnels = [];
let selected = null;     // name of the tunnel shown or being edited; null while adding a new one
let details = null;      // overview of the selected tunnel
let savedConfig = "";    // config as loaded into the editor, to detect edits
let busy = false;

function showError(message) {
  ui.error.textContent = message || "";
  ui.error.hidden = !message;
}

async function run(work) {
  if (busy) return;
  busy = true;
  setButtons();
  showError("");
  try {
    await work();
  } catch (e) {
    showError(String(e));
  } finally {
    busy = false;
    setButtons();
  }
}

function show(view) {
  ui.empty.hidden = view !== "empty";
  ui.details.hidden = view !== "details";
  ui.editor.hidden = view !== "editor";
  if (view !== "editor") {
    // Don't keep the private key in the page longer than needed.
    ui.config.value = "";
    savedConfig = "";
  }
}

function current() {
  return tunnels.find((t) => t.name === selected);
}

// ---- Sidebar ----

function renderList() {
  ui.list.replaceChildren(...tunnels.map((t) => {
    const li = document.createElement("li");
    li.className = t.name === selected ? "selected" : "";
    const label = document.createElement("span");
    label.className = "label";
    label.textContent = t.name;
    li.append(dot(t.connected), label);
    li.onclick = () => open(t.name);
    return li;
  }));
}

function dot(on) {
  const d = document.createElement("span");
  d.className = "dot" + (on ? " on" : "");
  d.title = on ? "Connected" : "Disconnected";
  return d;
}

async function refresh() {
  try {
    tunnels = await invoke("list_tunnels");
  } catch (e) {
    showError(String(e));
    return;
  }
  renderList();
  if (!ui.details.hidden) renderInterface();
  setButtons();
}

// ---- Overview ----

/// Fills a <dl> with label/value rows, skipping empty values.
function fields(dl, rows) {
  dl.replaceChildren(...rows.flatMap(([label, value, mono]) => {
    if (value == null || value === "" || (Array.isArray(value) && value.length === 0)) return [];
    const dt = document.createElement("dt");
    dt.textContent = label + ":";
    const dd = document.createElement("dd");
    if (value instanceof Node) {
      dd.append(value);
    } else {
      dd.textContent = Array.isArray(value) ? value.join(", ") : String(value);
    }
    if (mono) dd.className = "mono";
    return [dt, dd];
  }));
}

function renderInterface() {
  if (!details) return;
  const t = current();
  const status = document.createElement("span");
  status.className = "status";
  status.append(dot(t && t.connected), document.createTextNode(t && t.connected ? "Active" : "Inactive"));

  ui.dName.textContent = selected;
  fields(ui.dInterface, [
    ["Status", status],
    ["Public key", details.publicKey, true],
    ["Listen port", details.listenPort],
    ["Addresses", details.addresses],
    ["DNS servers", details.dns],
    ["MTU", details.mtu],
  ]);
  ui.toggle.textContent = t && t.connected ? "Deactivate" : "Activate";
}

function renderPeers() {
  ui.dPeers.replaceChildren(...details.peers.map((p) => {
    const card = document.createElement("div");
    card.className = "card";
    const title = document.createElement("h2");
    title.className = "card-title";
    title.textContent = "Peer";
    const dl = document.createElement("dl");
    dl.className = "fields";
    fields(dl, [
      ["Public key", p.publicKey, true],
      ["Preshared key", p.hasPresharedKey ? "enabled" : null],
      ["Allowed IPs", p.allowedIps],
      ["Endpoint", p.endpoint],
      ["Persistent keepalive", p.persistentKeepalive ? `every ${p.persistentKeepalive} seconds` : null],
    ]);
    card.append(title, dl);
    return card;
  }));
}

async function loadDetails(name) {
  details = await invoke("tunnel_details", { name });
  selected = name;
  show("details");
  renderInterface();
  renderPeers();
  renderList();
}

function open(name) {
  return run(() => loadDetails(name));
}

// ---- Editor ----

function setButtons() {
  const dirty = selected === null || ui.config.value !== savedConfig;
  ui.save.disabled = busy || !dirty || !ui.name.value.trim() || !ui.config.value.trim();
  ui.toggle.disabled = busy;
  ui.edit.disabled = busy;
  ui.del.disabled = busy;
}

async function edit() {
  await run(async () => {
    const text = await invoke("read_tunnel", { name: selected });
    show("editor");
    ui.name.value = selected;
    ui.name.readOnly = true;
    ui.config.value = text;
    // Compare against what the text box reports: it turns CRLF line endings into LF, which would
    // otherwise look like an unsaved edit.
    savedConfig = ui.config.value;
    validate();
  });
}

function startNew() {
  selected = null;
  details = null;
  show("editor");
  ui.name.value = "";
  ui.name.readOnly = false;
  ui.config.value = "";
  ui.check.textContent = "";
  ui.check.className = "check";
  renderList();
  setButtons();
  ui.name.focus();
}

function cancel() {
  if (selected) {
    open(selected);
  } else {
    show("empty");
  }
}

let validateTimer;
function validate() {
  clearTimeout(validateTimer);
  validateTimer = setTimeout(async () => {
    const text = ui.config.value;
    if (!text.trim()) {
      ui.check.textContent = "";
      ui.check.className = "check";
      return;
    }
    try {
      await invoke("validate", { config: text });
      ui.check.textContent = "✓ Config looks good";
      ui.check.className = "check ok";
    } catch (e) {
      ui.check.textContent = String(e);
      ui.check.className = "check bad";
    }
  }, 250);
  setButtons();
}

// ---- Behave like an app, not a web page ----

// Links open in the default browser; the window itself never navigates away. auxclick covers
// middle-clicks, which would otherwise open a second browser window.
function openLinksOutside(e) {
  const link = e.target.closest("a[href]");
  if (!link) return;
  e.preventDefault();
  invoke("open_link", { url: link.href }).catch((err) => showError(String(err)));
}
document.addEventListener("click", openLinksOutside);
document.addEventListener("auxclick", openLinksOutside);

// No browser menu (print, save page, reload…); text fields keep theirs for copy and paste.
document.addEventListener("contextmenu", (e) => {
  if (!e.target.closest("input, textarea")) e.preventDefault();
});

// No browser shortcuts: print, save page, find, reload, zoom-out-of-layout.
document.addEventListener("keydown", (e) => {
  const key = e.key.toLowerCase();
  const ctrl = e.ctrlKey || e.metaKey;
  if (key === "f5" || (ctrl && ["p", "s", "f", "r", "g", "j", "u"].includes(key))) {
    e.preventDefault();
  }
});

// ---- Wiring ----

ui.add.onclick = startNew;
ui.edit.onclick = edit;
ui.cancel.onclick = cancel;
ui.config.oninput = validate;
ui.name.oninput = setButtons;

ui.importFile.onchange = async () => {
  const file = ui.importFile.files[0];
  ui.importFile.value = "";
  if (!file) return;
  ui.config.value = await file.text();
  if (selected === null && !ui.name.value.trim()) {
    ui.name.value = file.name.replace(/\.conf$/i, "");
  }
  validate();
};

ui.save.onclick = () => run(async () => {
  const name = ui.name.value.trim();
  await invoke("save_tunnel", { name, config: ui.config.value });
  await refresh();
  await loadDetails(name);
});

ui.del.onclick = () => {
  if (!confirm(`Delete tunnel "${selected}"? Its config will be removed from this PC.`)) return;
  run(async () => {
    await invoke("remove_tunnel", { name: selected });
    selected = null;
    details = null;
    show("empty");
    await refresh();
  });
};

ui.toggle.onclick = () => run(async () => {
  const t = current();
  if (!t) return;
  ui.toggle.textContent = t.connected ? "Deactivating…" : "Activating…";
  await invoke(t.connected ? "disconnect" : "connect", { name: t.name });
  await refresh();
});

// Keep the status current, including changes made from Settings or the command line.
refresh();
setInterval(() => { if (!busy) refresh(); }, 3000);
