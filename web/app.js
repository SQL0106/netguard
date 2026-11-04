"use strict";

const $ = (id) => document.getElementById(id);

const DAYS = ["一", "二", "三", "四", "五", "六", "日"];

let snapshot = null;
let config = null;
let authenticated = false;
let clockOffset = 0;

function toast(message, isError) {
  const box = document.createElement("div");
  box.className = isError ? "toast error" : "toast";
  box.textContent = message;
  document.body.appendChild(box);
  window.setTimeout(() => box.remove(), 4200);
}

async function api(method, path, payload) {
  const options = { method, headers: {} };
  if (payload !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(payload);
  }
  const response = await fetch(path, options);
  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { error: text };
    }
  }
  if (!response.ok) {
    throw new Error((data && data.error) || response.statusText || "请求失败");
  }
  return data || {};
}

function fmtTime(seconds) {
  if (!seconds) return "—";
  const date = new Date((seconds + clockOffset) * 1000);
  return date.toLocaleString("zh-CN", { hour12: false });
}

function fmtDuration(seconds) {
  if (seconds === null || seconds === undefined) return "—";
  const total = Math.max(0, Math.round(seconds));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h} 小时 ${m} 分`;
  if (m > 0) return `${m} 分 ${s} 秒`;
  return `${s} 秒`;
}

function hhmm(minutes) {
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}`;
}

function parseHhmm(value) {
  const match = /^(\d{1,2}):(\d{2})$/.exec(String(value).trim());
  if (!match) return null;
  const h = Number(match[1]);
  const m = Number(match[2]);
  if (h > 24 || m > 59) return null;
  const total = h * 60 + m;
  if (total > 1440) return null;
  return total;
}

function dayList(mask) {
  const names = [];
  for (let index = 0; index < 7; index += 1) {
    if (mask & (1 << index)) names.push(DAYS[index]);
  }
  return names.length === 0 ? "未选择" : `周${names.join("、")}`;
}

function windowText(window) {
  return `${dayList(window.days)} ${hhmm(window.start)}–${hhmm(window.end)}${
    window.end < window.start ? "（跨日）" : ""
  }`;
}

function scheduleText(app) {
  const windows = (app.schedule && app.schedule.windows) || [];
  if (windows.length === 0) return "全天受管";
  return windows.map(windowText).join("；");
}

function showBanner(text, level) {
  const banner = $("banner");
  if (!text) {
    banner.classList.add("hidden");
    return;
  }
  banner.className = `banner ${level || ""}`.trim();
  banner.textContent = text;
}

function renderStatus() {
  if (!snapshot) return;
  const enabled = $("st-enabled");
  enabled.textContent = snapshot.enabled ? "已启用" : "已停用";
  enabled.className = "value " + (snapshot.enabled ? "ok" : "warn");

  const phase = $("st-phase");
  if (!snapshot.initialized) {
    phase.textContent = "未初始化";
    phase.className = "value warn";
  } else if (snapshot.overridden) {
    phase.textContent = "临时放行";
    phase.className = "value warn";
  } else if (snapshot.blocked && snapshot.blocked.length > 0) {
    phase.textContent = `拦截 ${snapshot.blocked.length} 项`;
    phase.className = "value danger";
  } else {
    phase.textContent = "正常";
    phase.className = "value ok";
  }

  const next = $("st-next");
  if (snapshot.next_change) {
    const delta = snapshot.next_change - Math.floor(Date.now() / 1000) - clockOffset;
    next.textContent = delta > 0 ? fmtDuration(delta) : fmtTime(snapshot.next_change);
    next.title = fmtTime(snapshot.next_change);
  } else {
    next.textContent = "无";
  }

  const integrity = $("st-integrity");
  integrity.textContent = snapshot.integrity_ok ? "通过" : "异常";
  integrity.className = "value " + (snapshot.integrity_ok ? "ok" : "danger");
  if (!snapshot.integrity_ok && snapshot.integrity_note) {
    showBanner(`配置完整性校验未通过：${snapshot.integrity_note}。系统保持封锁状态。`, "danger");
  } else if (snapshot.last_error) {
    showBanner(`运行告警：${snapshot.last_error}`, "warn");
  } else if (snapshot.overridden) {
    showBanner(`临时放行至 ${fmtTime(snapshot.override_until)}。`, "warn");
  } else {
    showBanner("");
  }

  const body = $("apps-body");
  body.textContent = "";
  const apps = snapshot.apps || [];
  if (apps.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 4;
    cell.className = "muted";
    cell.textContent = "尚未配置应用。";
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }
  for (const app of apps) {
    const row = document.createElement("tr");
    const name = document.createElement("td");
    name.textContent = app.name || "（未命名）";
    const path = document.createElement("td");
    path.className = "mono";
    path.textContent = app.path;
    const state = document.createElement("td");
    const tag = document.createElement("span");
    tag.className = "tag " + (app.blocked ? "blocked" : "allowed");
    tag.textContent = app.blocked ? "已拦截" : "可访问";
    state.appendChild(tag);
    const schedule = document.createElement("td");
    schedule.className = "muted";
    schedule.textContent = scheduleText(app);
    row.append(name, path, state, schedule);
    body.appendChild(row);
  }
}

function dayPicker(mask, onChange) {
  const wrap = document.createElement("div");
  wrap.className = "days";
  for (let index = 0; index < 7; index += 1) {
    const label = document.createElement("label");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.checked = (mask & (1 << index)) !== 0;
    input.addEventListener("change", () => {
      const next = input.checked ? mask | (1 << index) : mask & ~(1 << index);
      onChange(next);
    });
    label.append(input, document.createTextNode(DAYS[index]));
    wrap.appendChild(label);
  }
  return wrap;
}

function renderEditor() {
  const body = $("edit-body");
  body.textContent = "";
  if (!config) return;

  config.apps.forEach((app, appIndex) => {
    const row = document.createElement("tr");
    const nameCell = document.createElement("td");
    const nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.value = app.name || "";
    nameInput.addEventListener("input", () => {
      app.name = nameInput.value;
    });
    nameCell.appendChild(nameInput);

    const pathCell = document.createElement("td");
    const pathInput = document.createElement("input");
    pathInput.type = "text";
    pathInput.className = "mono";
    pathInput.value = app.path || "";
    pathInput.addEventListener("input", () => {
      app.path = pathInput.value;
    });
    pathCell.appendChild(pathInput);

    const scheduleCell = document.createElement("td");
    const windows = app.schedule.windows;
    if (windows.length === 0) {
      const note = document.createElement("div");
      note.className = "muted";
      note.textContent = "全天受管";
      scheduleCell.appendChild(note);
    }
    windows.forEach((window, windowIndex) => {
      const line = document.createElement("div");
      line.style.display = "flex";
      line.style.gap = "6px";
      line.style.alignItems = "center";
      line.style.marginBottom = "6px";

      line.appendChild(
        dayPicker(window.days, (mask) => {
          window.days = mask;
        })
      );

      const start = document.createElement("input");
      start.type = "text";
      start.value = hhmm(window.start);
      start.style.width = "64px";
      start.addEventListener("change", () => {
        const value = parseHhmm(start.value);
        if (value === null) {
          toast("时间格式应为 HH:MM", true);
          start.value = hhmm(window.start);
          return;
        }
        window.start = value;
      });

      const dash = document.createElement("span");
      dash.textContent = "–";

      const end = document.createElement("input");
      end.type = "text";
      end.value = hhmm(window.end);
      end.style.width = "64px";
      end.addEventListener("change", () => {
        const value = parseHhmm(end.value);
        if (value === null) {
          toast("时间格式应为 HH:MM", true);
          end.value = hhmm(window.end);
          return;
        }
        window.end = value === 0 ? 1440 : value;
      });

      const remove = document.createElement("button");
      remove.className = "ghost";
      remove.textContent = "×";
      remove.title = "删除时间窗";
      remove.addEventListener("click", () => {
        windows.splice(windowIndex, 1);
        renderEditor();
      });

      line.append(start, dash, end, remove);
      scheduleCell.appendChild(line);
    });

    const actions = document.createElement("td");
    const addWindow = document.createElement("button");
    addWindow.className = "ghost";
    addWindow.textContent = "加时间窗";
    addWindow.addEventListener("click", () => {
      windows.push({ days: 127, start: 0, end: 1440 });
      renderEditor();
    });
    const removeApp = document.createElement("button");
    removeApp.className = "danger";
    removeApp.textContent = "删除";
    removeApp.style.marginLeft = "6px";
    removeApp.addEventListener("click", () => {
      config.apps.splice(appIndex, 1);
      renderEditor();
    });
    actions.append(addWindow, removeApp);

    row.append(nameCell, pathCell, scheduleCell, actions);
    body.appendChild(row);
  });
}

function applySnapshot(data) {
  snapshot = data;
  clockOffset = (data.now || Math.floor(Date.now() / 1000)) - Math.floor(Date.now() / 1000);
  authenticated = Boolean(data.authenticated);
  $("clock").textContent = fmtTime(data.now);

  $("setup").classList.toggle("hidden", !data.setup_open || data.initialized);
  const needsLogin = data.initialized && data.factors !== "none" && !authenticated;
  $("login").classList.toggle("hidden", !needsLogin);
  $("st-enabled").parentElement.classList.toggle("hidden", false);
  $("login-pw").parentElement.classList.toggle("hidden", !data.needs_password);
  $("login-totp").parentElement.classList.toggle("hidden", !data.needs_totp);
  $("auth-pw").parentElement.classList.toggle("hidden", !data.needs_password);
  $("auth-totp").parentElement.classList.toggle("hidden", !data.needs_totp);
  $("totp-pw").parentElement.classList.toggle("hidden", !data.needs_password);

  const editable = authenticated || data.factors === "none";
  for (const id of ["apps", "security", "logs"]) {
    $(id).classList.toggle("hidden", !editable);
  }
  renderStatus();
}

async function refresh() {
  try {
    const data = await api("GET", "/api/state");
    applySnapshot(data);
    if ((authenticated || data.factors === "none") && !config) {
      await loadConfig();
    }
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

async function loadConfig() {
  try {
    config = await api("GET", "/api/config");
    renderEditor();
  } catch (error) {
    config = null;
  }
}

function credentialsFromFields(pwField, totpField) {
  const payload = {};
  const pw = $(pwField).value.trim();
  const totp = $(totpField).value.trim();
  if (pw) payload.pw = pw;
  if (totp) payload.totp = totp;
  return payload;
}

async function login() {
  const payload = {};
  const pw = $("login-pw").value;
  const totp = $("login-totp").value.trim();
  const recovery = $("login-recovery").value.trim();
  if (pw) payload.pw = pw;
  if (totp) payload.totp = totp;
  if (recovery) payload.recovery = recovery;
  try {
    const result = await api("POST", "/api/login", payload);
    $("login-pw").value = "";
    $("login-totp").value = "";
    $("login-recovery").value = "";
    $("auth-pw").value = "";
    $("auth-totp").value = "";
    toast(result.message || "登录成功");
    config = null;
    await refresh();
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

async function saveConfig() {
  if (!config) return;
  const payload = { config };
  Object.assign(payload, credentialsFromFields("auth-pw", "auth-totp"));
  try {
    await api("PUT", "/api/config", payload);
    toast("配置已保存");
    $("auth-totp").value = "";
    await refresh();
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

async function applyOverride(minutes) {
  const payload = { minutes };
  Object.assign(payload, credentialsFromFields("auth-pw", "auth-totp"));
  try {
    const result = await api("POST", "/api/override", payload);
    toast(minutes === 0 ? "已取消临时放行" : `临时放行至 ${fmtTime(result.until)}`);
    await refresh();
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

async function regenerateTotp() {
  const payload = { regenerate: true };
  Object.assign(payload, credentialsFromFields("totp-pw", "auth-totp"));
  try {
    const result = await api("POST", "/api/totp", payload);
    $("secret-box").classList.remove("hidden");
    $("secret-uri").textContent = result.uri || "";
    const box = $("secret-codes");
    box.textContent = "";
    (result.recovery_codes || []).forEach((code) => {
      const cell = document.createElement("div");
      cell.className = "code";
      cell.textContent = code;
      box.appendChild(cell);
    });
    toast("TOTP 密钥已重新生成，请立即保存恢复码");
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

async function regenerateRecovery() {
  const payload = { regenerate_recovery: true };
  Object.assign(payload, credentialsFromFields("totp-pw", "auth-totp"));
  try {
    const result = await api("POST", "/api/totp", payload);
    $("secret-box").classList.remove("hidden");
    $("secret-uri").textContent = result.uri || "";
    const box = $("secret-codes");
    box.textContent = "";
    (result.recovery_codes || []).forEach((code) => {
      const cell = document.createElement("div");
      cell.className = "code";
      cell.textContent = code;
      box.appendChild(cell);
    });
    toast("恢复码已重新生成");
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

async function submitSetup() {
  const payload = { factors: $("setup-factor").value };
  const pw = $("setup-pw").value;
  const secret = $("setup-totp").value.trim();
  if (pw) payload.pw = pw;
  if (secret) payload.totp_secret = secret;
  try {
    const result = await api("POST", "/api/setup", payload);
    $("setup-result").classList.remove("hidden");
    $("setup-uri").textContent = result.uri || "";
    const box = $("setup-codes");
    box.textContent = "";
    (result.recovery_codes || []).forEach((code) => {
      const cell = document.createElement("div");
      cell.className = "code";
      cell.textContent = code;
      box.appendChild(cell);
    });
    toast("初始化完成");
    await refresh();
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

async function loadLog() {
  try {
    const lines = Number($("log-lines").value) || 120;
    const result = await api("GET", `/api/log?lines=${lines}`);
    const body = Array.isArray(result.lines) ? result.lines.join("\n") : String(result.text || "");
    $("log-body").textContent = body || "（空）";
  } catch (error) {
    toast(String(error.message || error), true);
  }
}

async function logout() {
  try {
    await api("POST", "/api/logout", {});
  } catch {
    /* 会话已失效时忽略 */
  }
  config = null;
  await refresh();
}

function bind() {
  $("login-submit").addEventListener("click", login);
  $("save-config").addEventListener("click", saveConfig);
  $("override-apply").addEventListener("click", () => {
    applyOverride(Number($("ov-minutes").value) || 0);
  });
  $("override-cancel").addEventListener("click", () => applyOverride(0));
  $("regen-totp").addEventListener("click", regenerateTotp);
  $("regen-recovery").addEventListener("click", regenerateRecovery);
  $("setup-submit").addEventListener("click", submitSetup);
  $("log-refresh").addEventListener("click", loadLog);
  $("logout").addEventListener("click", logout);
  $("add-app").addEventListener("click", () => {
    if (!config) return;
    config.apps.push({ name: "", path: "", schedule: { windows: [] } });
    renderEditor();
  });
  $("login-recovery").addEventListener("keydown", (event) => {
    if (event.key === "Enter") login();
  });
}

bind();
refresh();
window.setInterval(refresh, 20000);
