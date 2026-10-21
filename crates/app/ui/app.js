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
  toggle: $("toggle"), edit: $("edit"), del: $("delete"), keepAwake: $("keep-awake"), alwaysOn: $("always-on"),
  dApps: $("d-apps"), dDns: $("d-dns"), addApp: $("add-app"), addDns: $("add-dns"), dnsSuffix: $("dns-suffix"),
  triggersElsewhere: $("triggers-elsewhere"),
  editor: $("editor"), name: $("name"), nameNote: $("name-note"), config: $("config"), check: $("check"),
  importFile: $("import"), cancel: $("cancel"), save: $("save"), error: $("error"),
  generate: $("generate"), pubkey: $("pubkey"), pubkeyValue: $("pubkey-value"),
  version: $("version"), openLog: $("open-log"),
};

let tunnels = [];
const pending = new Set(); // tunnels we are connecting or disconnecting right now
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

/// "disconnected", "connecting" or "connected", counting our own in-flight toggles as connecting.
function stateOf(t) {
  if (!t) return "disconnected";
  return pending.has(t.name) ? "connecting" : t.state;
}

const STATE_LABELS = { connected: "Connected", connecting: "Connecting…", disconnected: "Not connected" };

let renderedList = "";

function renderList() {
  // The list is polled every few seconds; rebuilding it each time would drop keyboard focus,
  // so only rebuild when something changed, and put focus back on the same toggle when it did.
  const key = JSON.stringify([selected, tunnels.map((t) => [t.name, stateOf(t)])]);
  if (key === renderedList) return;
  renderedList = key;
  const focused = document.activeElement?.dataset?.tunnel;

  ui.list.replaceChildren(...tunnels.map((t) => {
    const state = stateOf(t);
    const li = document.createElement("li");
    li.className = t.name === selected ? "selected" : "";
    const label = document.createElement("span");
    label.className = "label";
    label.textContent = t.name;

    const toggle = document.createElement("button");
    toggle.className = `switch ${state}`;
    toggle.title = `${STATE_LABELS[state]} — click to ${state === "disconnected" ? "connect" : "disconnect"}`;
    toggle.setAttribute("role", "switch");
    toggle.setAttribute("aria-checked", state === "connected" ? "true" : "false");
    toggle.setAttribute("aria-label", `${t.name}: ${STATE_LABELS[state]}`);
    toggle.dataset.tunnel = t.name;
    toggle.onclick = (e) => {
      e.stopPropagation();
      toggleTunnel(t);
    };

    li.append(label, toggle);
    li.onclick = () => open(t.name);
    return li;
  }));

  if (focused) {
    [...ui.list.querySelectorAll(".switch")].find((s) => s.dataset.tunnel === focused)?.focus();
  }
}

/// While adding, a name that already exists (Windows ignores case) would replace that tunnel.
function nameTaken() {
  const name = ui.name.value.trim().toLowerCase();
  return selected === null && name !== "" && tunnels.some((t) => t.name.toLowerCase() === name);
}

function dot(state) {
  const d = document.createElement("span");
  d.className = `dot ${state}`;
  return d;
}

/// Connects or disconnects a tunnel. Connecting one disconnects any other Tunnelik tunnel, since
/// Windows only runs one connection per VPN plugin.
async function toggleTunnel(t) {
  if (pending.has(t.name)) return;
  const action = stateOf(t) === "disconnected" ? "connect" : "disconnect";
  pending.add(t.name);
  showError("");
  renderAll();
  try {
    await invoke(action, { name: t.name });
  } catch (e) {
    showError(String(e));
  } finally {
    pending.delete(t.name);
    await refresh();
  }
}

function renderAll() {
  renderList();
  if (!ui.details.hidden) renderInterface();
}

async function refresh() {
  try {
    tunnels = await invoke("list_tunnels");
  } catch (e) {
    showError(String(e));
    return;
  }
  renderAll();
  setButtons();
  await refreshLive();
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
  const state = stateOf(current());
  const status = document.createElement("span");
  status.className = "status";
  let label = { connected: "Active", connecting: "Working…", disconnected: "Inactive" }[state];
  if (state === "connected" && live?.keepingAwake) label += ", keeping the PC awake";
  status.append(dot(state), document.createTextNode(label));

  ui.dName.textContent = selected;
  ui.keepAwake.checked = details.keepAwake;
  ui.alwaysOn.checked = details.alwaysOn;
  fields(ui.dInterface, [
    ["Status", status],
    ["Public key", details.publicKey, true],
    ["Listen port", details.listenPort],
    ["Addresses", details.addresses],
    ["DNS servers", details.dnsServers],
    ["Search domains", details.dnsSearch],
    ["MTU", details.mtu],
  ]);
  ui.toggle.textContent = state === "disconnected" ? "Activate" : "Deactivate";
  ui.toggle.disabled = busy || state === "connecting";
}

/// A row in the "start on its own" lists, with its remove button.
function triggerRow(main, sub, remove) {
  const li = document.createElement("li");
  const name = document.createElement("span");
  name.className = "trigger-main";
  name.textContent = main;
  const detail = document.createElement("span");
  detail.className = "trigger-sub";
  detail.textContent = sub;
  const button = document.createElement("button");
  button.className = "button";
  button.textContent = "Remove";
  button.setAttribute("aria-label", `Remove ${main}`);
  button.disabled = busy;
  button.onclick = () => run(async () => {
    await remove();
    await loadDetails(selected);
  });
  li.append(name, detail, button);
  return li;
}

function renderTriggers() {
  const t = details.triggers;
  ui.triggersElsewhere.hidden = !t.elsewhere;
  ui.triggersElsewhere.textContent = t.elsewhere
    ? `Right now "${t.elsewhere}" is the tunnel that starts on its own. Remove its programs and domains to use this one instead.`
    : "";
  ui.dApps.replaceChildren(...t.apps.map((program) => triggerRow(
    program.split(/[\\/]/).pop(), program,
    () => invoke("remove_app_trigger", { name: selected, program }))));
  ui.dDns.replaceChildren(...t.dns.map((suffix) => triggerRow(
    suffix, "any name under this domain",
    () => invoke("remove_dns_trigger", { name: selected, suffix }))));
}

let live = null;          // the plugin's status while the selected tunnel is connected

function renderPeers() {
  ui.dPeers.replaceChildren(...details.peers.map((p) => {
    const card = document.createElement("div");
    card.className = "card";
    const title = document.createElement("h2");
    title.className = "card-title";
    title.textContent = "Peer";
    const dl = document.createElement("dl");
    dl.className = "fields";
    const now = live && live.peers.find((l) => l.publicKey === p.publicKey);
    fields(dl, [
      ["Public key", p.publicKey, true],
      ["Preshared key", p.hasPresharedKey ? "enabled" : null],
      ["Allowed IPs", p.allowedIps],
      ["Endpoint", p.endpoint],
      ["Persistent keepalive", p.persistentKeepalive ? `every ${p.persistentKeepalive} seconds` : null],
      ["Latest handshake", now ? ago(now.lastHandshakeSecsAgo) : null],
      ["Transfer", now ? `${bytes(now.rxBytes)} received, ${bytes(now.txBytes)} sent` : null],
    ]);
    card.append(title, dl);
    return card;
  }));
}

function ago(secs) {
  if (secs == null) return "none yet";
  const parts = [];
  for (const [unit, size] of [["hour", 3600], ["minute", 60], ["second", 1]]) {
    const n = Math.floor(secs / size);
    secs -= n * size;
    if (n || (unit === "second" && !parts.length)) parts.push(`${n} ${unit}${n === 1 ? "" : "s"}`);
  }
  return parts.join(", ") + " ago";
}

function bytes(n) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return i === 0 ? `${n} B` : `${n.toFixed(2)} ${units[i]}`;
}

/// Fetches the plugin's latest counters for the open tunnel, and redraws the peers if they
/// changed. Cheap: it reads a small file the plugin rewrites every 2 seconds.
async function refreshLive() {
  if (!details || ui.details.hidden) return;
  const next = stateOf(current()) === "connected"
    ? await invoke("tunnel_live", { name: selected }).catch(() => null)
    : null;
  if (JSON.stringify(next) !== JSON.stringify(live)) {
    live = next;
    renderInterface();
    renderPeers();
  }
}

async function loadDetails(name) {
  details = await invoke("tunnel_details", { name });
  selected = name;
  live = null;
  show("details");
  renderInterface();
  renderTriggers();
  renderPeers();
  renderList();
  await refreshLive();
}

function open(name) {
  return run(() => loadDetails(name));
}

// ---- Editor ----

function setButtons() {
  const dirty = selected === null || ui.config.value !== savedConfig;
  const taken = nameTaken();
  ui.nameNote.hidden = !taken;
  ui.nameNote.textContent = taken ? `A tunnel named "${ui.name.value.trim()}" already exists. Pick another name, or edit that tunnel instead.` : "";
  ui.save.disabled = busy || !dirty || taken || !ui.name.value.trim() || !ui.config.value.trim();
  ui.toggle.disabled = busy || stateOf(current()) === "connecting";
  ui.edit.disabled = busy;
  ui.del.disabled = busy;
  ui.keepAwake.disabled = busy;
  ui.alwaysOn.disabled = busy;
  const elsewhere = !!details?.triggers?.elsewhere;
  ui.addApp.disabled = busy || elsewhere;
  ui.addDns.disabled = busy || elsewhere || !ui.dnsSuffix.value.trim();
  ui.generate.disabled = busy;
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
  showPublicKey(null);
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
      showPublicKey(null);
      return;
    }
    try {
      const publicKey = await invoke("validate", { config: text });
      ui.check.textContent = "✓ Config looks good";
      ui.check.className = "check ok";
      showPublicKey(publicKey);
    } catch (e) {
      ui.check.textContent = String(e);
      ui.check.className = "check bad";
      showPublicKey(null);
    }
  }, 250);
  setButtons();
}

/// The public key of the private key in the box: what the server side needs to know.
function showPublicKey(key) {
  ui.pubkey.hidden = !key;
  ui.pubkeyValue.textContent = key || "";
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

// A new private key goes straight into the config box; the public key shows under it.
ui.generate.onclick = () => run(async () => {
  if (ui.config.value.includes("PrivateKey") &&
      !confirm("Replace the private key in this config? Peers will need the new public key.")) {
    return;
  }
  const generated = await invoke("generate_key", { config: ui.config.value });
  ui.config.value = generated.config;
  validate();
});

ui.openLog.onclick = () => invoke("open_log_folder").catch((e) => showError(String(e)));
invoke("app_version").then((v) => { ui.version.textContent = v ? `v${v}` : ""; }).catch(() => {});

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

ui.toggle.onclick = () => {
  const t = current();
  if (t) toggleTunnel(t);
};

// Both options are saved straight away; the connected tunnel picks them up within seconds.
function option(box, command, field) {
  box.onchange = () => run(async () => {
    const enabled = box.checked;
    try {
      await invoke(command, { name: selected, enabled });
      details[field] = enabled;
    } catch (e) {
      box.checked = details[field];
      throw e;
    }
  });
}
option(ui.keepAwake, "set_keep_awake", "keepAwake");
option(ui.alwaysOn, "set_always_on", "alwaysOn");

// Programs and domains that start the tunnel. The program comes from a native file dialog,
// since the page itself never learns real paths.
ui.addApp.onclick = () => run(async () => {
  const program = await invoke("pick_program");
  if (!program) return;
  await invoke("add_app_trigger", { name: selected, program });
  await loadDetails(selected);
});
ui.dnsSuffix.oninput = setButtons;
ui.dnsSuffix.onkeydown = (e) => { if (e.key === "Enter" && !ui.addDns.disabled) ui.addDns.click(); };
ui.addDns.onclick = () => run(async () => {
  const suffix = ui.dnsSuffix.value.trim();
  if (!suffix) return;
  await invoke("add_dns_trigger", { name: selected, suffix });
  ui.dnsSuffix.value = "";
  await loadDetails(selected);
});

// After a reinstall Windows may have dropped the VPN connections; bring them back quietly.
invoke("repair_profiles")
  .then((names) => { if (names.length) refresh(); })
  .catch((e) => showError(String(e)));

// Keep the status current, including changes made from Settings or the command line.
refresh();
setInterval(() => { if (!busy) refresh(); }, 3000);
