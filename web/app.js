const state = {
  baseUrl: localStorage.getItem("sos_base_url") || window.location.origin,
  token: localStorage.getItem("sos_token") || "",
  location: null,
};
let toastTimer = null;

const el = {
  routeLogin: document.getElementById("routeLogin"),
  routeSignup: document.getElementById("routeSignup"),
  routeApp: document.getElementById("routeApp"),
  routeHistory: document.getElementById("routeHistory"),
  routeDevices: document.getElementById("routeDevices"),

  loginForm: document.getElementById("loginForm"),
  registerForm: document.getElementById("registerForm"),

  goHistory: document.getElementById("goHistory"),
  goDevices: document.getElementById("goDevices"),
  goDevicesFromHistory: document.getElementById("goDevicesFromHistory"),
  goApp: document.getElementById("goApp"),
  goAppFromDevices: document.getElementById("goAppFromDevices"),
  goHistoryFromDevices: document.getElementById("goHistoryFromDevices"),
  logoutBtn: document.getElementById("logoutBtn"),
  logoutBtn2: document.getElementById("logoutBtn2"),
  logoutBtn3: document.getElementById("logoutBtn3"),

  detectLocation: document.getElementById("detectLocation"),
  triggerSOSBig: document.getElementById("triggerSOSBig"),
  locationState: document.getElementById("locationState"),
  lastSend: document.getElementById("lastSend"),
  deviceLinkForm: document.getElementById("deviceLinkForm"),
  deviceUid: document.getElementById("deviceUid"),
  deviceName: document.getElementById("deviceName"),
  deviceTokenInfo: document.getElementById("deviceTokenInfo"),
  connectedDeviceBadge: document.getElementById("connectedDeviceBadge"),
  disconnectDeviceBtn: document.getElementById("disconnectDeviceBtn"),

  refreshHistory: document.getElementById("refreshHistory"),
  historyList: document.getElementById("historyList"),

  saveBase: document.getElementById("saveBase"),
  apiBase: document.getElementById("apiBase"),
  tokenPreview: document.getElementById("tokenPreview"),

  flash: document.getElementById("flash"),
  confirmModal: document.getElementById("confirmModal"),
  confirmTitle: document.getElementById("confirmTitle"),
  confirmMessage: document.getElementById("confirmMessage"),
  confirmCancel: document.getElementById("confirmCancel"),
  confirmOk: document.getElementById("confirmOk"),
};

function flash(message, kind = "ok") {
  el.flash.className = `flash ${kind === "err" ? "err" : "ok"} show`;
  el.flash.textContent = message;
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.flash.classList.remove("show");
  }, 2400);
}

function confirmPopup(message, title = "Confirm Action") {
  return new Promise((resolve) => {
    if (!el.confirmModal || !el.confirmMessage || !el.confirmOk || !el.confirmCancel) {
      resolve(true);
      return;
    }
    el.confirmTitle.textContent = title;
    el.confirmMessage.textContent = message;
    el.confirmModal.classList.add("show");

    const close = (value) => {
      el.confirmModal.classList.remove("show");
      el.confirmOk.removeEventListener("click", onOk);
      el.confirmCancel.removeEventListener("click", onCancel);
      el.confirmModal.removeEventListener("click", onBackdrop);
      resolve(value);
    };
    const onOk = () => close(true);
    const onCancel = () => close(false);
    const onBackdrop = (ev) => {
      if (ev.target === el.confirmModal) close(false);
    };

    el.confirmOk.addEventListener("click", onOk);
    el.confirmCancel.addEventListener("click", onCancel);
    el.confirmModal.addEventListener("click", onBackdrop);
  });
}

function saveState() {
  localStorage.setItem("sos_base_url", state.baseUrl);
  localStorage.setItem("sos_token", state.token);
}

function setHash(path) {
  if (location.hash !== `#${path}`) location.hash = `#${path}`;
}

function getPath() {
  const hash = location.hash || "#/login";
  return hash.startsWith("#/") ? hash.slice(1) : "/login";
}

function renderRoute() {
  const path = getPath();
  [el.routeLogin, el.routeSignup, el.routeApp, el.routeHistory, el.routeDevices].forEach((p) => p.classList.remove("active"));
  if (path === "/signup") el.routeSignup.classList.add("active");
  else if (path === "/app") el.routeApp.classList.add("active");
  else if (path === "/history") el.routeHistory.classList.add("active");
  else if (path === "/devices") el.routeDevices.classList.add("active");
  else el.routeLogin.classList.add("active");
}

function guardRoute() {
  const path = getPath();
  if (!state.token && (path === "/app" || path === "/history" || path === "/devices")) {
    setHash("/login");
    return;
  }
  if (state.token && (path === "/login" || path === "/signup")) {
    setHash("/app");
    return;
  }
  renderRoute();
  if (path === "/history") loadHistory();
}

function updateTopRow() {
  if (el.apiBase) el.apiBase.value = state.baseUrl;
  if (el.tokenPreview) {
    el.tokenPreview.textContent = state.token ? `${state.token.slice(0, 24)}...` : "Not logged in";
  }
}

async function request(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body && !(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  if (state.token) headers.set("Authorization", `Bearer ${state.token}`);

  const res = await fetch(`${state.baseUrl}${path}`, { ...options, headers });
  const text = await res.text();
  let data = {};
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (!res.ok) throw new Error(`${res.status}: ${data.detail || res.statusText}`);
  return data;
}

function setLocationUI() {
  if (!state.location) {
    el.locationState.textContent = "Location: unknown";
    return;
  }
  el.locationState.textContent = `Location: ${state.location.latitude.toFixed(5)}, ${state.location.longitude.toFixed(5)}`;
}

function captureLocation() {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error("Geolocation not supported"));
      return;
    }
    navigator.geolocation.getCurrentPosition(
      (pos) => {
        state.location = { latitude: pos.coords.latitude, longitude: pos.coords.longitude };
        setLocationUI();
        resolve(state.location);
      },
      (err) => reject(new Error(err.message || "Location failed")),
      { enableHighAccuracy: true, timeout: 12000 }
    );
  });
}

async function sendSOS() {
  try {
    const loc = await captureLocation();
    await request("/sos/create", { method: "POST", body: JSON.stringify(loc) });
    el.lastSend.textContent = `Last alert sent: ${new Date().toLocaleString()}`;
    flash("SOS sent.");
  } catch (error) {
    flash(`SOS failed: ${error.message}`, "err");
  }
}

function renderHistory(items) {
  el.historyList.innerHTML = "";
  if (!Array.isArray(items) || items.length === 0) {
    el.historyList.innerHTML = "<li>No alerts yet.</li>";
    return;
  }
  items.forEach((it) => {
    const li = document.createElement("li");
    const created = it.created_at ? new Date(it.created_at).toLocaleString() : "N/A";
    li.innerHTML = `<strong>${it.status || "active"}</strong><br>Lat: ${Number(it.latitude).toFixed(5)} | Lon: ${Number(it.longitude).toFixed(5)}<br><small>${created}</small>`;
    el.historyList.appendChild(li);
  });
}

async function loadHistory() {
  try {
    const data = await request("/sos/my-alerts");
    renderHistory(data);
  } catch (error) {
    flash(`History failed: ${error.message}`, "err");
  }
}

async function refreshDeviceInfo() {
  if (!state.token || !el.deviceTokenInfo) return;
  try {
    const devices = await request("/devices/my");
    if (!Array.isArray(devices) || devices.length === 0) {
      el.deviceTokenInfo.textContent = "No device connected yet.";
      if (el.connectedDeviceBadge) el.connectedDeviceBadge.textContent = "Device: none";
      if (el.disconnectDeviceBtn) el.disconnectDeviceBtn.disabled = true;
      return;
    }
    const d = devices[0];
    el.deviceTokenInfo.textContent = `Linked: ${d.device_uid} | Token: ${d.device_token}`;
    if (el.connectedDeviceBadge) el.connectedDeviceBadge.textContent = `Device: ${d.device_uid}`;
    if (el.disconnectDeviceBtn) {
      el.disconnectDeviceBtn.disabled = false;
      el.disconnectDeviceBtn.dataset.deviceUid = d.device_uid;
    }
  } catch (error) {
    el.deviceTokenInfo.textContent = "Could not load device info.";
    if (el.connectedDeviceBadge) el.connectedDeviceBadge.textContent = "Device: unavailable";
  }
}

if (el.saveBase && el.apiBase) {
  el.saveBase.addEventListener("click", () => {
    state.baseUrl = el.apiBase.value.trim().replace(/\/$/, "") || window.location.origin;
    saveState();
    updateTopRow();
    flash("API base saved.");
  });
}

el.loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const fd = new FormData(el.loginForm);
  const body = new URLSearchParams();
  body.set("username", String(fd.get("phone") || ""));
  body.set("password", String(fd.get("password") || ""));
  try {
    const data = await request("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    state.token = data.access_token || "";
    saveState();
    updateTopRow();
    refreshDeviceInfo();
    setHash("/app");
    flash("Logged in.");
  } catch (error) {
    flash(`Login failed: ${error.message}`, "err");
  }
});

el.registerForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = Object.fromEntries(new FormData(el.registerForm).entries());
  try {
    await request("/auth/register", { method: "POST", body: JSON.stringify(payload) });

    const body = new URLSearchParams();
    body.set("username", String(payload.phone));
    body.set("password", String(payload.password));
    const data = await request("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });

    state.token = data.access_token || "";
    saveState();
    updateTopRow();
    refreshDeviceInfo();
    setHash("/app");
    flash("Account created.");
  } catch (error) {
    flash(`Sign up failed: ${error.message}`, "err");
  }
});

if (el.deviceLinkForm) {
  el.deviceLinkForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const payload = {
      device_uid: String(el.deviceUid.value || "").trim(),
      device_name: String(el.deviceName.value || "").trim() || null,
    };
    try {
      const data = await request("/devices/link", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      el.deviceTokenInfo.textContent = `Linked: ${data.device_uid} | Token: ${data.device_token}`;
      flash("Device connected. Copy token to NodeMCU firmware.");
    } catch (error) {
      flash(`Device link failed: ${error.message}`, "err");
    }
  });
}

if (el.disconnectDeviceBtn) {
  el.disconnectDeviceBtn.addEventListener("click", async () => {
    const deviceUid = el.disconnectDeviceBtn.dataset.deviceUid || "";
    if (!deviceUid) {
      flash("No connected device to disconnect.", "err");
      return;
    }
    const ok = await confirmPopup(`Disconnect ${deviceUid}?`, "Disconnect Device");
    if (!ok) return;
    try {
      await request("/devices/unlink", {
        method: "POST",
        body: JSON.stringify({ device_uid: deviceUid }),
      });
      flash("Device disconnected.");
      refreshDeviceInfo();
    } catch (error) {
      flash(`Disconnect failed: ${error.message}`, "err");
    }
  });
}

function logout() {
  state.token = "";
  saveState();
  updateTopRow();
  if (el.deviceTokenInfo) el.deviceTokenInfo.textContent = "No device connected yet.";
  if (el.connectedDeviceBadge) el.connectedDeviceBadge.textContent = "Device: none";
  if (el.disconnectDeviceBtn) {
    el.disconnectDeviceBtn.disabled = true;
    el.disconnectDeviceBtn.dataset.deviceUid = "";
  }
  setHash("/login");
  flash("Logged out.");
}

el.logoutBtn.addEventListener("click", logout);
el.logoutBtn2.addEventListener("click", logout);
el.logoutBtn3.addEventListener("click", logout);
el.goHistory.addEventListener("click", () => setHash("/history"));
el.goDevices.addEventListener("click", () => setHash("/devices"));
el.goDevicesFromHistory.addEventListener("click", () => setHash("/devices"));
el.goApp.addEventListener("click", () => setHash("/app"));
el.goAppFromDevices.addEventListener("click", () => setHash("/app"));
el.goHistoryFromDevices.addEventListener("click", () => setHash("/history"));
el.refreshHistory.addEventListener("click", loadHistory);
el.detectLocation.addEventListener("click", async () => {
  try {
    await captureLocation();
    flash("Location updated.");
  } catch (error) {
    flash(`Location failed: ${error.message}`, "err");
  }
});
el.triggerSOSBig.addEventListener("click", sendSOS);

window.addEventListener("hashchange", guardRoute);
updateTopRow();
setLocationUI();
if (!location.hash) setHash(state.token ? "/app" : "/login");
guardRoute();
refreshDeviceInfo();
flash("Ready.");
