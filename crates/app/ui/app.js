// Tunnelik's UI. Talks to the Rust side through Tauri commands (src/main.rs).
const { invoke } = window.__TAURI__.core;

const $ = (id) => document.getElementById(id);
const ui = {
  list: $("tunnels"), add: $("new"), empty: $("empty"), editor: $("editor"),
  name: $("name"), state: $("state"), toggle: $("toggle"), config: $("config"),
  check: $("check"), importFile: $("import"), del: $("delete"), save: $("save"), error: $("error"),
};

let tunnels = [];
let selected = null;     // name of the open tunnel, or null for a new one
let savedConfig = "";    // config as last loaded or saved, to detect edits
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

function current() {
  return tunnels.find((t) => t.name === selected);
}

function renderList() {
  ui.list.replaceChildren(...tunnels.map((t) => {
    const li = document.createElement("li");
    li.className = t.name === selected ? "selected" : "";
    const dot = document.createElement("span");
    dot.className = "dot" + (t.connected ? " on" : "");
    dot.title = t.connected ? "Connected" : "Disconnected";
    const label = document.createElement("span");
    label.className = "label";
    label.textContent = t.name;
    li.append(dot, label);
    li.onclick = () => open(t.name);
    return li;
  }));
}

function renderState() {
  const t = current();
  ui.state.textContent = t ? (t.connected ? "Connected" : "Disconnected") : "";
  ui.state.className = "state" + (t && t.connected ? " on" : "");
  ui.toggle.hidden = !t;
  ui.toggle.textContent = t && t.connected ? "Disconnect" : "Connect";
  setButtons();
}

function setButtons() {
  const dirty = ui.config.value !== savedConfig || selected === null;
  ui.save.disabled = busy || !dirty || !ui.name.value.trim() || !ui.config.value.trim();
  ui.del.hidden = selected === null;
  ui.del.disabled = busy;
  ui.toggle.disabled = busy || (ui.config.value !== savedConfig);
}

async function refresh() {
  try {
    tunnels = await invoke("list_tunnels");
  } catch (e) {
    showError(String(e));
    return;
  }
  renderList();
  renderState();
}

async function open(name) {
  await run(async () => {
    const text = await invoke("read_tunnel", { name });
    selected = name;
    ui.name.value = name;
    ui.name.readOnly = true;
    ui.config.value = text;
    // Compare against what the text box reports: it turns CRLF line endings into LF, which would
    // otherwise look like an unsaved edit and keep Connect disabled.
    savedConfig = ui.config.value;
    showEditor();
    validate();
    renderList();
    renderState();
  });
}

function startNew() {
  selected = null;
  savedConfig = "";
  ui.name.value = "";
  ui.name.readOnly = false;
  ui.config.value = "";
  ui.check.textContent = "";
  ui.check.className = "check";
  showEditor();
  renderList();
  renderState();
  ui.name.focus();
}

function showEditor() {
  ui.empty.hidden = true;
  ui.editor.hidden = false;
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

ui.add.onclick = startNew;
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
  selected = name;
  savedConfig = ui.config.value;
  ui.name.readOnly = true;
  await refresh();
});

ui.del.onclick = () => {
  if (!confirm(`Delete tunnel "${selected}"? Its config will be removed from this PC.`)) return;
  run(async () => {
    await invoke("remove_tunnel", { name: selected });
    selected = null;
    ui.editor.hidden = true;
    ui.empty.hidden = false;
    await refresh();
  });
};

ui.toggle.onclick = () => run(async () => {
  const t = current();
  if (!t) return;
  ui.state.textContent = t.connected ? "Disconnecting…" : "Connecting…";
  await invoke(t.connected ? "disconnect" : "connect", { name: t.name });
  await refresh();
});

// Keep the connected dots current, including changes made from Settings or the command line.
refresh();
setInterval(() => { if (!busy) refresh(); }, 3000);
