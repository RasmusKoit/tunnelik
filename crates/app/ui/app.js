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
  dApps: $("d-apps"), addApp: $("add-app"), groupPrograms: $("group-programs"),
  dDestinations: $("d-destinations"), addDestination: $("add-destination"), destination: $("destination"),
  triggersElsewhere: $("triggers-elsewhere"), triggersOff: $("triggers-off"), triggersOn: $("triggers-on"),
  triggersStop: $("triggers-stop"),
  editor: $("editor"), name: $("name"), nameNote: $("name-note"), config: $("config"), check: $("check"),
  importFile: $("import"), cancel: $("cancel"), save: $("save"), error: $("error"),
  generate: $("generate"), pubkey: $("pubkey"), pubkeyValue: $("pubkey-value"),
  version: $("version"), openLog: $("open-log"), notice: $("notice"),
};

let tunnels = [];
const pending = new Map(); // tunnel name → "connect" or "disconnect", while we do it
let selected = null;     // name of the tunnel shown or being edited; null while adding a new one
let details = null;      // overview of the selected tunnel
let savedConfig = "";    // config as loaded into the editor, to detect edits
// The PrivateKey line Generate key last put in, and its public key; shown while that line stays.
let generated = null;
let busy = false;

/// Messages come from the code the command line shares, where `backticks` mark a value; here
/// quotes read better, and a message starts with a capital like a sentence.
function readable(message) {
  const text = String(message ?? "").replace(/`([^`]*)`/g, "“$1”");
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function showError(message) {
  ui.error.textContent = message ? readable(message) : "";
  ui.error.hidden = !message;
}

async function run(work) {
  if (busy) return;
  busy = true;
  // Disabling the pressed button sends focus to the page; put it back afterwards.
  const focused = document.activeElement;
  setButtons();
  showError("");
  ui.notice.textContent = "";
  try {
    await work();
  } catch (e) {
    showError(String(e));
  } finally {
    busy = false;
    setButtons();
    restoreFocus(focused);
  }
}

/// Puts focus back where it was, or on the next sensible control when that one went away.
function restoreFocus(element) {
  if (document.activeElement !== document.body) return;
  if (element?.isConnected && !element.disabled && element.offsetParent) element.focus();
  else (!ui.editor.hidden ? ui.config : ui.details.hidden ? ui.add : ui.toggle).focus({ preventScroll: true });
}

function show(view) {
  ui.empty.hidden = view !== "empty";
  ui.details.hidden = view !== "details";
  ui.editor.hidden = view !== "editor";
  if (view !== "editor") {
    // Don't keep the private key in the page longer than needed.
    ui.config.value = "";
    savedConfig = "";
    generated = null;
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

/// A tunnel's state in words; our own disconnect shows as such rather than as "Connecting…".
function stateLabel(t) {
  return pending.get(t?.name) === "disconnect" ? "Disconnecting…" : STATE_LABELS[stateOf(t)];
}

let renderedList = "";

function renderList() {
  // The list is polled every few seconds; rebuilding it each time would drop keyboard focus,
  // so only rebuild when something changed, and put focus back on the same toggle when it did.
  const key = JSON.stringify([selected, tunnels.map((t) => [t.name, stateOf(t)])]);
  if (key === renderedList) return;
  renderedList = key;
  const focused = document.activeElement?.dataset?.tunnel;
  const kind = document.activeElement?.classList?.contains("label") ? ".label" : ".switch";

  ui.list.replaceChildren(...tunnels.map((t) => {
    const state = stateOf(t);
    const li = document.createElement("li");
    li.className = t.name === selected ? "selected" : "";
    // A real button, so the keyboard and screen readers can open the tunnel too.
    const label = document.createElement("button");
    label.className = "label";
    label.textContent = t.name;
    label.title = t.name;
    label.dataset.tunnel = t.name;
    if (t.name === selected) label.setAttribute("aria-current", "true");
    label.onclick = (e) => {
      e.stopPropagation();
      if (!busy && discardOk()) open(t.name);
    };

    const toggle = document.createElement("button");
    toggle.className = `switch ${state}`;
    toggle.title = `${stateLabel(t)} — click to ${state === "disconnected" ? "connect" : "disconnect"}`;
    toggle.setAttribute("role", "switch");
    toggle.setAttribute("aria-checked", state === "connected" ? "true" : "false");
    toggle.setAttribute("aria-label", `${t.name}: ${stateLabel(t)}`);
    toggle.dataset.tunnel = t.name;
    toggle.onclick = (e) => {
      e.stopPropagation();
      toggleTunnel(t);
    };

    li.append(label, toggle);
    li.onclick = () => label.click();
    return li;
  }));

  if (focused) {
    [...ui.list.querySelectorAll(kind)].find((s) => s.dataset.tunnel === focused)?.focus();
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
  const focused = document.activeElement;
  const others = action === "connect"
    ? tunnels.filter((o) => o.name !== t.name && o.state !== "disconnected").map((o) => `"${o.name}"`)
    : [];
  pending.set(t.name, action);
  showError("");
  ui.notice.textContent = "";
  renderAll();
  try {
    await invoke(action, { name: t.name });
    if (others.length) ui.notice.textContent = `${others.join(", ")} was disconnected: one Tunnelik tunnel runs at a time.`;
  } catch (e) {
    showError(String(e));
  } finally {
    pending.delete(t.name);
    await refresh();
    restoreFocus(focused);
  }
}

/// Text being selected in the overview, e.g. a key to copy; a redraw would drop it.
function selecting() {
  const s = document.getSelection();
  return !!s && !s.isCollapsed && ui.details.contains(s.anchorNode);
}

function renderAll() {
  $("empty-title").textContent = tunnels.length ? "No tunnel selected" : "No tunnels yet";
  renderList();
  if (!ui.details.hidden && !selecting()) renderInterface();
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
  let label = stateLabel(current());
  if (state === "connected" && live?.keepingAwake) label += ", keeping the PC awake";
  // Windows says connected once the plugin runs; only a handshake shows the server answered.
  if (state === "connected" && live?.peers.length && live.peers.every((p) => p.lastHandshakeSecsAgo == null && p.rxBytes === 0)) {
    label += ", no handshake with the server yet";
  }
  status.append(dot(state), document.createTextNode(label));

  ui.dName.textContent = selected;
  ui.keepAwake.checked = details.keepAwake;
  ui.alwaysOn.checked = details.alwaysOn;
  fields(ui.dInterface, [
    ["Status", status],
    ["Protocol", details.protocol],
    ["Public key", details.publicKey, true],
    ["Listen port", details.listenPort],
    ["Addresses", details.addresses],
    ["DNS servers", details.dnsServers],
    ["Search domains", details.dnsSearch],
    ["MTU", details.mtu],
    // AmneziaWG's settings, when the config has any.
    ...details.obfuscation,
  ]);
  ui.toggle.textContent = state === "disconnected" ? "Connect" : "Disconnect";
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
  if (sub) detail.title = sub;
  const button = document.createElement("button");
  button.className = "button small";
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
  // Windows' side (programs, domains) needs its switch; subnets are Tunnelik's own and always
  // work, so the destinations group always shows.
  ui.triggersOff.hidden = t.enabled;
  ui.triggersStop.hidden = !t.enabled;
  // Windows keeps dialing for what it was given while the service is off (after a restart, say),
  // so those stay listed instead of looking switched off.
  const held = t.apps.length > 0 || t.dns.length > 0;
  ui.groupPrograms.hidden = !t.enabled && t.apps.length === 0;
  ui.triggersElsewhere.hidden = t.enabled ? !t.elsewhere : !held;
  ui.triggersElsewhere.textContent = !t.enabled && held
    ? "Windows still starts this tunnel for these. Turn the helper service on to change them."
    : t.elsewhere
      ? `Right now "${t.elsewhere}" is the tunnel Windows starts on its own. Remove its programs and domains to use this one instead.`
      : "";
  ui.dApps.replaceChildren(...t.apps.map((program) => triggerRow(
    program.split(/[\\/]/).pop(), program,
    () => invoke("remove_app_trigger", { name: selected, program }))));
  ui.dDestinations.replaceChildren(
    ...t.dns.map((suffix) => triggerRow(suffix, "domain",
      () => invoke("remove_dns_trigger", { name: selected, suffix }))),
    ...t.subnets.map((cidr) => triggerRow(cidr, "range",
      () => invoke("remove_subnet_trigger", { name: selected, cidr }))));
}

/// A destination typed into the box: an address or range goes to the subnet watcher, anything
/// else is a domain; the Rust side checks either properly.
function isRange(text) {
  return text.includes(":") || /^\d+\.\d+\.\d+\.\d+(\/\d+)?$/.test(text);
}

let live = null;          // the plugin's status while the selected tunnel is connected

function renderPeers() {
  ui.dPeers.replaceChildren(...details.peers.map((p, i) => {
    const card = document.createElement("div");
    card.className = "card";
    const title = document.createElement("h2");
    title.className = "card-title";
    // Told apart for heading navigation when there are several.
    title.textContent = details.peers.length > 1 ? `Peer ${i + 1}${p.endpoint ? `: ${p.endpoint}` : ""}` : "Peer";
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
  const name = selected;
  const next = stateOf(current()) === "connected"
    ? await invoke("tunnel_live", { name }).catch(() => null)
    : null;
  // Another tunnel was opened meanwhile, or a key is being selected to copy.
  if (name !== selected || ui.details.hidden || selecting()) return;
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

/// Whether the editor holds text that leaving would lose: an edited config, or anything typed
/// for a new tunnel.
function unsaved() {
  if (ui.editor.hidden) return false;
  return ui.config.value !== savedConfig || (selected === null && ui.name.value.trim() !== "");
}

/// Asks before throwing away unsaved edits; true when it is fine to leave the editor.
function discardOk() {
  return !unsaved() || confirm("Discard your changes? A key generated here is lost with them.");
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
  ui.addApp.disabled = busy || elsewhere || !details?.triggers?.enabled;
  ui.addDestination.disabled = busy || !ui.destination.value.trim();
  ui.triggersOn.disabled = busy;
  ui.triggersStop.disabled = busy;
  // The rows are rendered while a change is still in flight, so they follow `busy` from here.
  for (const button of document.querySelectorAll(".triggers button")) button.disabled = busy;
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
  if (!discardOk()) return;
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
      ui.check.textContent = readable(e);
      ui.check.className = "check bad";
      // A config still being written has no Address or [Peer] yet, but its key can be handed out.
      showPublicKey(generated && text.includes(generated.line) ? generated.publicKey : null);
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

// No browser menu (print, save page, reload…); text fields and selected text keep theirs, for
// copy and paste.
document.addEventListener("contextmenu", (e) => {
  if (!e.target.closest("input, textarea") && document.getSelection().isCollapsed) e.preventDefault();
});

// No browser shortcuts: print, save page, find, reload, zoom-out-of-layout.
document.addEventListener("keydown", (e) => {
  const key = e.key.toLowerCase();
  const ctrl = e.ctrlKey || e.metaKey;
  // In the editor, Ctrl+S saves and Escape cancels, as in other Windows editors.
  if (!ui.editor.hidden && ctrl && key === "s") {
    e.preventDefault();
    if (!ui.save.disabled) ui.save.click();
    return;
  }
  if (!ui.editor.hidden && key === "escape") {
    cancel();
    return;
  }
  if (key === "f5" || (ctrl && ["p", "s", "f", "r", "g", "j", "u"].includes(key))) {
    e.preventDefault();
  }
});

// ---- Wiring ----

// Not while a save is in flight: its loadDetails would replace the new editor a moment later.
ui.add.onclick = () => { if (!busy && discardOk()) startNew(); };
ui.edit.onclick = edit;
ui.cancel.onclick = cancel;
ui.config.oninput = validate;
ui.name.oninput = setButtons;

// Notepad's "Unicode" is UTF-16 with a byte order mark; `tunnelik add` reads it too.
async function readText(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const encoding = bytes[0] === 0xff && bytes[1] === 0xfe ? "utf-16le"
    : bytes[0] === 0xfe && bytes[1] === 0xff ? "utf-16be" : "utf-8";
  return new TextDecoder(encoding, { fatal: true }).decode(bytes);
}

$("import-button").onclick = () => ui.importFile.click();
ui.importFile.onchange = async () => {
  const file = ui.importFile.files[0];
  ui.importFile.value = "";
  if (!file) return;
  try {
    ui.config.value = await readText(file);
  } catch {
    return showError(`"${file.name}" is not UTF-8 text; save it as UTF-8 and import it again.`);
  }
  if (selected === null && !ui.name.value.trim()) {
    // Only characters a tunnel name may have: "wg0 (1).conf" becomes "wg0 1".
    ui.name.value = file.name.replace(/\.conf$/i, "").replace(/[^A-Za-z0-9 ._-]/g, "")
      .replace(/^[\s.]+/, "").trim().slice(0, 64);
  }
  validate();
};

// A new private key goes straight into the config box; the public key shows under it.
ui.generate.onclick = () => run(async () => {
  // Keys are case-insensitive in the parser, so `privatekey =` is a key to protect too.
  if (/^\s*privatekey\s*=/im.test(ui.config.value) &&
      !confirm("Replace the private key in this config? Peers will need the new public key.")) {
    return;
  }
  const result = await invoke("generate_key", { config: ui.config.value });
  ui.config.value = result.config;
  const line = result.config.match(/^\s*PrivateKey\s*=.*$/im)?.[0].trim();
  generated = line ? { line, publicKey: result.publicKey } : null;
  validate();
});

ui.openLog.onclick = () => invoke("open_log_folder").catch((e) => showError(String(e)));
invoke("app_version").then((v) => { ui.version.textContent = v ? `v${v}` : ""; }).catch(() => {});

ui.save.onclick = () => run(async () => {
  const name = ui.name.value.trim();
  const wasUp = stateOf(tunnels.find((t) => t.name === name)) !== "disconnected";
  await invoke("save_tunnel", { name, config: ui.config.value });
  await refresh();
  await loadDetails(name);
  if (wasUp) ui.notice.textContent = `Saved. "${name}" uses the new settings once you reconnect it.`;
});

ui.del.onclick = () => {
  const up = stateOf(current()) !== "disconnected";
  if (!confirm(`Delete "${selected}"${up ? " and disconnect it" : ""}? Its config and private key are removed from this PC; this can't be undone.`)) return;
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
// The feature itself is a switch: starting or stopping the helper service, with Windows'
// administrator prompt in between.
ui.triggersOn.onclick = () => run(async () => {
  ui.triggersOn.textContent = "Waiting for approval…";
  try {
    await invoke("enable_triggers", { enabled: true });
  } finally {
    ui.triggersOn.textContent = "Turn on…";
  }
  await loadDetails(selected);
});
ui.triggersStop.onclick = () => run(async () => {
  if (!confirm("Stop the helper service? Windows keeps starting tunnels for the programs and domains they already have.")) return;
  await invoke("enable_triggers", { enabled: false });
  await loadDetails(selected);
});
ui.destination.oninput = setButtons;
ui.destination.onkeydown = (e) => { if (e.key === "Enter" && !ui.addDestination.disabled) ui.addDestination.click(); };
ui.addDestination.onclick = () => run(async () => {
  const text = ui.destination.value.trim();
  if (!text) return;
  if (isRange(text)) {
    await invoke("add_subnet_trigger", { name: selected, cidr: text });
  } else {
    await invoke("add_dns_trigger", { name: selected, suffix: text });
  }
  ui.destination.value = "";
  await loadDetails(selected);
});

// After a reinstall Windows may have dropped the VPN connections; bring them back quietly.
invoke("repair_profiles")
  .then((names) => { if (names.length) refresh(); })
  .catch((e) => showError(String(e)));

// Keep the status current, including changes made from Settings or the command line.
refresh().then(() => {
  // Open on a tunnel rather than an empty page: the connected one, else the first.
  if (selected === null && ui.editor.hidden && tunnels.length) {
    open((tunnels.find((t) => t.state !== "disconnected") ?? tunnels[0]).name);
  }
});
setInterval(() => { if (!busy) refresh(); }, 3000);
