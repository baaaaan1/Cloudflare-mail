
// main.js - Glassmorphism mail client UI for Cloudflare Email Panel
const defaultConfig = {
  panel_title: 'Cloudflare Email Panel',
  welcome_message: 'Manage routing and inbox in one place'
};

const state = {
  rules: [],
  ruleMap: new Map(),
  addresses: [],
  selectedAddress: null,
  addressActivity: {},
  inbox: [],
  inboxPage: 0,
  inboxLimit: 20,
  domains: [],
  domainsLoaded: false,
  workers: [],
  workersLoaded: false,
  workersError: null,
  editingRuleId: null,
  editingRuleZoneId: null,
  currentEmailId: null,
  currentEmailData: null
};

let authMode = 'token';
let authOptions = {
  token: true,
  tfa: true,
  password: false,
  authRequired: false,
  tokenExpired: false,
  tfaExpired: false,
  registerPending: false,
  registerExpiresAt: null
};
let registerCooldownTimer = null;
let registerPollTimer = null;

const accentPresets = {
  ocean: { accent: '#5aa9ff', accent2: '#7fd1ff', accent3: '#3c6fff' },
  purple: { accent: '#9b7bff', accent2: '#c0a0ff', accent3: '#6b4cff' },
  emerald: { accent: '#30c28a', accent2: '#6adbb1', accent3: '#1a8f69' },
  amber: { accent: '#f4a340', accent2: '#ffd089', accent3: '#d97706' }
};

const ADDRESS_SORT_KEY = 'addressSort';
const ADDRESS_ACTIVITY_KEY = 'addressActivity';

async function api(path, opts) {
  const headers = { 'Content-Type': 'application/json' };
  const res = await fetch(path, Object.assign({ headers, credentials: 'include' }, opts));
  if (res.status === 401) {
    setLoginVisible(true);
    throw new Error('Unauthorized');
  }
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  return res.json();
}

function setLoginVisible(show) {
  const modal = document.getElementById('loginModal');
  if (!modal) return;
  modal.classList.toggle('active', show);
  document.body.classList.toggle('login-active', show);
}

function showNotification(message, type = 'success') {
  const notification = document.createElement('div');
  notification.className = `notification ${type}`;
  const icon = document.createElement('span');
  icon.className = 'material-icons';
  icon.textContent = type === 'success' ? 'check_circle' : 'error';
  const text = document.createElement('span');
  text.textContent = message;
  notification.appendChild(icon);
  notification.appendChild(text);
  document.body.appendChild(notification);
  setTimeout(() => {
    notification.style.opacity = '0';
    notification.style.transform = 'translateX(100%)';
    setTimeout(() => notification.remove(), 300);
  }, 3000);
}

function clearLegacyAuthStorage() {
  try {
    localStorage.removeItem('accessToken');
    localStorage.removeItem('sessionId');
  } catch {}
}

function hexToRgb(hex) {
  const clean = hex.replace('#', '').trim();
  if (clean.length !== 6) return null;
  const num = parseInt(clean, 16);
  if (Number.isNaN(num)) return null;
  return { r: (num >> 16) & 255, g: (num >> 8) & 255, b: num & 255 };
}

function rgbToHex({ r, g, b }) {
  return `#${[r, g, b].map((v) => v.toString(16).padStart(2, '0')).join('')}`;
}

function shadeHex(hex, percent) {
  const rgb = hexToRgb(hex);
  if (!rgb) return hex;
  const amount = Math.round(255 * percent);
  return rgbToHex({
    r: Math.min(255, Math.max(0, rgb.r + amount)),
    g: Math.min(255, Math.max(0, rgb.g + amount)),
    b: Math.min(255, Math.max(0, rgb.b + amount))
  });
}

function applyAccentColors(accent, accent2, accent3) {
  const root = document.documentElement;
  root.style.setProperty('--accent', accent);
  root.style.setProperty('--accent-2', accent2);
  root.style.setProperty('--accent-3', accent3);
}

function setPresetActive(preset) {
  document.querySelectorAll('#themePresets .chip').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.preset === preset);
  });
}

function applyAccentPreset(preset) {
  const colors = accentPresets[preset];
  if (!colors) return;
  applyAccentColors(colors.accent, colors.accent2, colors.accent3);
  localStorage.setItem('accentPreset', preset);
  localStorage.removeItem('accentCustom');
  setPresetActive(preset);
  syncAccentInputs(colors.accent);
}

function applyCustomAccent(hex) {
  const clean = hex.startsWith('#') ? hex : `#${hex}`;
  if (!hexToRgb(clean)) return false;
  applyAccentColors(clean, shadeHex(clean, 0.2), shadeHex(clean, -0.2));
  localStorage.setItem('accentCustom', clean);
  localStorage.removeItem('accentPreset');
  setPresetActive(null);
  syncAccentInputs(clean);
  return true;
}

function loadAccentTheme() {
  const custom = localStorage.getItem('accentCustom');
  const preset = localStorage.getItem('accentPreset') || 'ocean';
  if (custom && applyCustomAccent(custom)) return;
  applyAccentPreset(preset);
}

function syncAccentInputs(hex) {
  const picker = document.getElementById('accentPicker');
  const display = document.getElementById('accentHexDisplay');
  if (picker) picker.value = hex;
  if (display) display.value = hex;
}

function loadAddressActivity() {
  try {
    const raw = localStorage.getItem(ADDRESS_ACTIVITY_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') return parsed;
  } catch {}
  return {};
}

function saveAddressActivity() {
  try {
    localStorage.setItem(ADDRESS_ACTIVITY_KEY, JSON.stringify(state.addressActivity || {}));
  } catch {}
}

function setAddressActivity(address, timestamp) {
  if (!address || !Number.isFinite(timestamp)) return;
  const key = address.toLowerCase();
  const current = state.addressActivity[key] || 0;
  if (timestamp > current) {
    state.addressActivity[key] = timestamp;
    saveAddressActivity();
  }
}

function getAddressActivity(address) {
  if (!address) return 0;
  return state.addressActivity[address.toLowerCase()] || 0;
}

function hasActivityData() {
  return Object.values(state.addressActivity).some((value) => Number(value) > 0);
}

const themeQuery = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;

function applyTheme(mode, persist = false) {
  const body = document.body;
  const isDark = mode === 'dark';
  body.classList.toggle('dark-mode', isDark);
  const themeIcon = document.getElementById('theme-icon');
  const themeText = document.getElementById('theme-text');
  if (themeIcon) themeIcon.textContent = isDark ? 'light_mode' : 'dark_mode';
  if (themeText) themeText.textContent = isDark ? 'Light' : 'Dark';
  if (persist) {
    localStorage.setItem('theme', mode);
  }
}

function toggleTheme() {
  const isDark = document.body.classList.contains('dark-mode');
  applyTheme(isDark ? 'light' : 'dark', true);
}

function loadTheme() {
  const savedTheme = localStorage.getItem('theme');
  if (savedTheme === 'dark' || savedTheme === 'light') {
    applyTheme(savedTheme, false);
  } else {
    const preferred = themeQuery && themeQuery.matches ? 'dark' : 'light';
    applyTheme(preferred, false);
    if (themeQuery) {
      themeQuery.addEventListener('change', (event) => {
        if (!localStorage.getItem('theme')) {
          applyTheme(event.matches ? 'dark' : 'light', false);
        }
      });
    }
  }
  loadAccentTheme();
}

const SIDEBAR_STATE_KEY = 'sidebarState';

function updateSidebarHandle(state) {
  const handleIcon = document.getElementById('sidebarHandleIcon');
  const handle = document.getElementById('sidebarHandle');
  const isOpen = state === 'open';
  if (handleIcon) handleIcon.textContent = isOpen ? 'chevron_left' : 'chevron_right';
  if (handle) handle.setAttribute('aria-expanded', String(isOpen));
}

function setSidebarState(state) {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebarOverlay');
  const isOpen = state === 'open';
  document.body.classList.toggle('sidebar-open', isOpen);
  if (sidebar) {
    sidebar.classList.toggle('is-open', isOpen);
    sidebar.classList.toggle('is-collapsed', !isOpen);
  }
  if (overlay) overlay.classList.toggle('is-open', isOpen);
  localStorage.setItem(SIDEBAR_STATE_KEY, state);
  updateSidebarHandle(state);
}

function toggleSidebar() {
  const current = document.body.classList.contains('sidebar-open') ? 'open' : 'collapsed';
  setSidebarState(current === 'open' ? 'collapsed' : 'open');
}

async function fetchAuthStatus() {
  try {
    const res = await fetch('/api/auth-status');
    if (!res.ok) return null;
    return await res.json();
  } catch {
    return null;
  }
}

function setAuthNotice(message, tone = 'warning') {
  const notice = document.getElementById('authNotice');
  if (!notice) return;
  if (!message) {
    notice.textContent = '';
    notice.className = 'auth-notice is-hidden';
    return;
  }
  notice.textContent = message;
  notice.className = `auth-notice ${tone}`;
  notice.classList.remove('is-hidden');
}

function isTokenUsable() {
  return authOptions.token && !authOptions.tokenExpired && !authOptions.registerPending;
}

function isTfaUsable() {
  return authOptions.tfa && !authOptions.tfaExpired && !authOptions.registerPending;
}

function isPasswordUsable() {
  return authOptions.password && !authOptions.registerPending;
}

async function checkSession() {
  try {
    await api('/api/session');
    return true;
  } catch {
    return false;
  }
}
function updateRegisterButton() {
  const btn = document.getElementById('btn-register-request');
  if (!btn) return;
  const expiresAt = authOptions.registerExpiresAt || parseInt(localStorage.getItem('registerCooldownUntil') || '0', 10);
  const now = Date.now();
  if (authOptions.registerPending && !expiresAt) {
    btn.disabled = true;
    btn.textContent = 'Request Pending (approve in bot)';
    return;
  }
  if (expiresAt && expiresAt > now) {
    btn.disabled = true;
    btn.textContent = 'Request Pending (approve in bot)';
  } else {
    btn.disabled = false;
    btn.textContent = 'Request Register (10m)';
    if (expiresAt && expiresAt <= now) {
      localStorage.removeItem('registerCooldownUntil');
      if (authOptions.registerPending) {
        authOptions.registerPending = false;
        authOptions.registerExpiresAt = null;
        if (authOptions.tokenExpired || authOptions.tfaExpired) {
          setAuthNotice('Login expired. Request a new token from the bot.', 'warning');
        } else {
          setAuthNotice('');
        }
        setLoginDisabled(false);
      }
    }
  }
  if (registerCooldownTimer) {
    clearTimeout(registerCooldownTimer);
    registerCooldownTimer = null;
  }
  if (expiresAt && expiresAt > now) {
    registerCooldownTimer = setTimeout(updateRegisterButton, expiresAt - now + 500);
  }
}

function setLoginDisabled(disabled) {
  const accessInput = document.getElementById('accessToken');
  const tfaInput = document.getElementById('tfaToken');
  const passwordInput = document.getElementById('passwordInput');
  const submitBtn = document.getElementById('loginSubmitBtn');
  if (accessInput) accessInput.disabled = disabled;
  if (tfaInput) tfaInput.disabled = disabled;
  if (passwordInput) passwordInput.disabled = disabled;
  if (submitBtn) submitBtn.disabled = disabled;
  document.querySelectorAll('.auth-toggle-btn').forEach((btn) => {
    const mode = btn.dataset.auth;
    const isUsable = mode === 'token' ? isTokenUsable() : mode === 'tfa' ? isTfaUsable() : isPasswordUsable();
    btn.disabled = disabled || !isUsable;
    btn.classList.toggle('disabled', btn.disabled);
  });
}

async function requestRegister() {
  const btn = document.getElementById('btn-register-request');
  if (!btn || btn.disabled) return;
  const originalText = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Requesting...';
  try {
    const res = await fetch('/api/register-request', { method: 'POST' });
    let data = null;
    try { data = await res.json(); } catch {}
    if (!res.ok) {
      if (res.status === 429 && data && data.expiresAt) {
        authOptions.registerPending = true;
        authOptions.registerExpiresAt = data.expiresAt;
        localStorage.setItem('registerCooldownUntil', String(data.expiresAt));
        setAuthNotice('Register request already pending. Approve in bot.', 'warning');
        setLoginDisabled(true);
        updateRegisterButton();
        return;
      }
      throw new Error((data && data.error) || res.statusText);
    }
    authOptions.registerPending = true;
    authOptions.registerExpiresAt = data && data.expiresAt ? data.expiresAt : null;
    if (authOptions.registerExpiresAt) {
      localStorage.setItem('registerCooldownUntil', String(authOptions.registerExpiresAt));
    }
    setAuthNotice('Request sent. Approve in bot to continue.', 'warning');
    setLoginDisabled(true);
    updateRegisterButton();
    startRegisterPolling();
  } catch (e) {
    showNotification('Register request failed: ' + e.message, 'error');
    btn.disabled = false;
    btn.textContent = originalText;
  }
}

function startRegisterPolling() {
  if (registerPollTimer) return;
  registerPollTimer = setInterval(async () => {
    const status = await fetchAuthStatus();
    if (!status) return;
    const wasPending = authOptions.registerPending;
    authOptions.registerPending = !!status.registerPending;
    authOptions.registerExpiresAt = status.registerExpiresAt || null;
    authOptions.token = !!status.accessTokenEnabled;
    authOptions.tfa = !!status.tfaEnabled;
    authOptions.password = !!status.passwordEnabled;
    authOptions.authRequired = !!status.authRequired;
    authOptions.tokenExpired = !!status.tokenExpired;
    authOptions.tfaExpired = !!status.tfaExpired;
    updateRegisterButton();
    if (!authOptions.registerPending) {
      if (authOptions.tokenExpired || authOptions.tfaExpired) {
        setAuthNotice('Login expired. Request a new token from the bot.', 'warning');
      } else {
        setAuthNotice('');
      }
      setLoginDisabled(false);
      setAuthMode(authMode);
      clearInterval(registerPollTimer);
      registerPollTimer = null;
    } else if (!wasPending) {
      setLoginDisabled(true);
    }
  }, 10000);
}

function setAuthMode(mode) {
  const preferred = mode;
  const candidates = preferred ? [preferred, 'token', 'tfa', 'password'] : ['token', 'tfa', 'password'];
  let resolved = preferred || 'token';
  for (const candidate of candidates) {
    if (candidate === 'token' && isTokenUsable()) { resolved = 'token'; break; }
    if (candidate === 'tfa' && isTfaUsable()) { resolved = 'tfa'; break; }
    if (candidate === 'password' && isPasswordUsable()) { resolved = 'password'; break; }
  }
  authMode = resolved;
  const accessGroup = document.getElementById('accessTokenGroup');
  const tfaGroup = document.getElementById('tfaTokenGroup');
  const accessInput = document.getElementById('accessToken');
  const tfaInput = document.getElementById('tfaToken');
  const passwordGroup = document.getElementById('passwordGroup');
  const passwordInput = document.getElementById('passwordInput');
  const submitBtn = document.getElementById('loginSubmitBtn');
  document.querySelectorAll('.auth-toggle-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.auth === authMode);
  });
  const isToken = authMode === 'token';
  const isTfa = authMode === 'tfa';
  const isPassword = authMode === 'password';
  if (accessGroup) accessGroup.classList.toggle('is-hidden', !isToken);
  if (tfaGroup) tfaGroup.classList.toggle('is-hidden', !isTfa);
  if (passwordGroup) passwordGroup.classList.toggle('is-hidden', !isPassword);
  if (accessInput) accessInput.required = isToken;
  if (tfaInput) tfaInput.required = isTfa;
  if (passwordInput) passwordInput.required = isPassword;
  if (submitBtn) submitBtn.textContent = isTfa ? 'Verify' : 'Login';
}

async function handleAuth(event) {
  event.preventDefault();
  if (authOptions.registerPending) {
    showNotification('Register request pending approval in bot.', 'error');
    return;
  }
  if (authMode === 'token') {
    if (!authOptions.token) {
      showNotification('Access key not available', 'error');
      return;
    }
    if (authOptions.tokenExpired) {
      showNotification('Access key expired. Generate a new token in the bot.', 'error');
      return;
    }
    const token = document.getElementById('accessToken').value.trim();
    if (!token) {
      showNotification('Access key required', 'error');
      return;
    }
    try {
      await api('/api/login', { method: 'POST', body: JSON.stringify({ token }) });
      setLoginVisible(false);
      loadRules();
    } catch (e) {
      showNotification('Login failed: ' + e.message, 'error');
    }
  } else if (authMode === 'password') {
    if (!authOptions.password) {
      showNotification('Password login not available', 'error');
      return;
    }
    const password = document.getElementById('passwordInput').value;
    if (!password) {
      showNotification('Password required', 'error');
      return;
    }
    try {
      await api('/api/login-password', { method: 'POST', body: JSON.stringify({ password }) });
      setLoginVisible(false);
      loadRules();
    } catch (e) {
      showNotification('Login failed: ' + e.message, 'error');
    }
  } else {
    if (!authOptions.tfa) {
      showNotification('2FA not available', 'error');
      return;
    }
    if (authOptions.tfaExpired) {
      showNotification('2FA expired. Generate a new token in the bot.', 'error');
      return;
    }
    const code = document.getElementById('tfaToken').value.trim();
    if (!code) {
      showNotification('2FA code required', 'error');
      return;
    }
    try {
      await api('/api/verify-2fa', { method: 'POST', body: JSON.stringify({ token: code }) });
      setLoginVisible(false);
      loadRules();
    } catch (e) {
      showNotification('2FA verification failed: ' + e.message, 'error');
    }
  }
}
function updateApiStatus(overallStatus = 'success', data = null) {
  const dot = document.querySelector('#api-status .status-dot');
  const desc = document.getElementById('api-status-desc');
  if (!dot || !desc) return;
  const now = new Date();
  const timeString = now.toLocaleTimeString();
  if (overallStatus === 'error') {
    dot.classList.remove('success');
    dot.classList.add('error');
    desc.textContent = `Offline - last checked ${timeString}`;
  } else {
    dot.classList.remove('error');
    dot.classList.add('success');
    desc.textContent = `Online - last checked ${timeString}`;
  }
  if (data && data.destinations !== undefined) {
    desc.textContent = `Routes: ${data.rules || 0} | Destinations: ${data.destinations || 0} (${timeString})`;
  }
}

function updateVisibilityIcon(button, isVisible) {
  const icon = button ? button.querySelector('.material-icons') : null;
  if (icon) icon.textContent = isVisible ? 'visibility_off' : 'visibility';
}

function toggleInputVisibility(input, button) {
  if (!input) return;
  const isPassword = input.type === 'password';
  input.type = isPassword ? 'text' : 'password';
  if (button) updateVisibilityIcon(button, isPassword);
}

function updateTokenToggleVisibility() {
  const input = document.getElementById('cfgApiToken');
  const button = document.getElementById('cfgApiTokenToggle');
  if (!input || !button) return;
  const hasValue = input.value.trim().length > 0;
  button.classList.toggle('is-hidden', !hasValue);
  if (!hasValue && input.type !== 'password') {
    input.type = 'password';
    updateVisibilityIcon(button, false);
  }
}

function handleSettingsAction(event) {
  const actionBtn = event.target.closest('button[data-action]');
  if (!actionBtn) return;
  const targetId = actionBtn.dataset.target;
  const action = actionBtn.dataset.action;
  const input = document.getElementById(targetId);
  if (!input) return;
  if (action === 'toggle-visibility') {
    toggleInputVisibility(input, actionBtn);
    return;
  }
  if (action === 'copy') {
    copyToClipboard(input.value.trim(), 'Disalin ke clipboard', 'Gagal menyalin');
  }
}
async function checkApiStatus(buttonEl) {
  const button = buttonEl;
  const originalContent = button.textContent;
  button.textContent = 'Checking...';
  button.disabled = true;
  try {
    const h = await api('/health');
    updateApiStatus(h.ok ? 'success' : 'error', h);
    showNotification('API status updated', h.ok ? 'success' : 'error');
  } catch (e) {
    updateApiStatus('error');
    showNotification('Health failed: ' + e.message, 'error');
  } finally {
    button.textContent = originalContent;
    button.disabled = false;
  }
}

async function loadSettings() {
  try {
    const config = await api('/api/config');
    document.getElementById('cfgAccountId').value = config.account_id || '';
    document.getElementById('cfgZoneId').value = config.zone_id || '';
    document.getElementById('cfgD1DatabaseId').value = config.d1_database_id || '';
    const tokenInput = document.getElementById('cfgApiToken');
    tokenInput.value = '';
    tokenInput.placeholder = config.has_token ? '******** (Set to update)' : 'Enter API Token';
    updateTokenToggleVisibility();
  } catch (e) {
    showNotification('Could not load config: ' + e.message, 'error');
  }
}

async function saveSettings(e) {
  e.preventDefault();
  const body = {
    account_id: document.getElementById('cfgAccountId').value.trim(),
    zone_id: document.getElementById('cfgZoneId').value.trim(),
    d1_database_id: document.getElementById('cfgD1DatabaseId').value.trim(),
    api_token: document.getElementById('cfgApiToken').value.trim()
  };
  try {
    await api('/api/config', { method: 'POST', body: JSON.stringify(body) });
    showNotification('Configuration saved!', 'success');
    loadDomains(true);
  } catch (err) {
    showNotification('Save failed: ' + err.message, 'error');
  }
}

async function loadDomains(force = false) {
  if (state.domainsLoaded && !force) return state.domains;
  try {
    const domains = await api('/api/domains');
    state.domains = Array.isArray(domains) ? domains : [];
  } catch (e) {
    state.domains = [];
  }
  state.domainsLoaded = true;
  updateDomainSelect();
  return state.domains;
}

async function loadWorkers(force = false) {
  if (state.workersLoaded && !force) return state.workers;
  try {
    const workers = await api('/api/workers');
    state.workers = Array.isArray(workers) ? workers : [];
    state.workersError = null;
  } catch (e) {
    state.workers = [];
    state.workersError = e.message || 'Gagal memuat worker';
  }
  state.workersLoaded = true;
  updateWorkerSelect();
  return state.workers;
}

function updateWorkerSelect(selectedName = null) {
  const select = document.getElementById('workerSelect');
  if (!select) return;
  select.innerHTML = '';
  if (!state.workersLoaded) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'Memuat worker...';
    select.appendChild(opt);
    select.disabled = true;
    return;
  }
  if (state.workersError) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'Gagal memuat worker';
    select.appendChild(opt);
    select.disabled = true;
    return;
  }
  if (!state.workers.length) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'Tidak ada worker ditemukan';
    select.appendChild(opt);
    select.disabled = true;
    return;
  }
  select.disabled = false;
  state.workers.forEach((worker) => {
    const name = worker.name || worker.id || '';
    if (!name) return;
    const opt = document.createElement('option');
    opt.value = name;
    opt.textContent = name;
    select.appendChild(opt);
  });
  if (selectedName) {
    const hasMatch = Array.from(select.options).some((opt) => opt.value === selectedName);
    if (!hasMatch) {
      const opt = document.createElement('option');
      opt.value = selectedName;
      opt.textContent = `${selectedName} (custom)`;
      select.appendChild(opt);
    }
    select.value = selectedName;
  }
}

function updateDomainSelect(selectedId = null) {
  const select = document.getElementById('fromDomain');
  if (!select) return;
  select.innerHTML = '';
  if (!state.domains.length) {
    select.disabled = true;
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'Domain list unavailable';
    select.appendChild(opt);
    return;
  }
  select.disabled = false;
  state.domains.forEach((domain) => {
    const opt = document.createElement('option');
    opt.value = domain.id;
    opt.textContent = domain.name;
    select.appendChild(opt);
  });
  if (selectedId) select.value = selectedId;
}

function getRuleMapKey(ruleId, zoneId) {
  return `${zoneId || 'default'}:${ruleId}`;
}

async function loadRules() {
  try {
    await loadDomains();
    let rules = [];
    if (state.domains.length) {
      const requests = state.domains.map((domain) =>
        api(`/api/rules?zoneId=${encodeURIComponent(domain.id)}`)
          .then((data) => ({ status: 'ok', domain, data }))
          .catch(() => ({ status: 'error', domain, data: [] }))
      );
      const results = await Promise.all(requests);
      results.forEach((result) => {
        if (result.status === 'ok') {
          result.data.forEach((rule) => {
            rule.zoneId = result.domain.id;
            rule.zoneName = result.domain.name;
            rules.push(rule);
          });
        }
      });
    } else {
      const data = await api('/api/rules');
      rules = data.map((rule) => ({ ...rule, zoneId: null, zoneName: '' }));
    }
    state.rules = rules;
    state.ruleMap = new Map();
    rules.forEach((rule) => {
      state.ruleMap.set(getRuleMapKey(rule.id, rule.zoneId), rule);
    });
    buildAddressList();
  } catch (e) {
    showNotification('Load rules failed: ' + e.message, 'error');
  }
}

function buildAddressList() {
  const map = new Map();
  state.rules.forEach((rule) => {
    const address = rule.matchers && rule.matchers[0] && rule.matchers[0].value;
    if (!address) return;
    const key = address.toLowerCase();
    const action = rule.actions && rule.actions[0] ? rule.actions[0] : {};
    const existing = map.get(key) || {
      address,
      count: 0,
      ruleId: rule.id,
      zoneId: rule.zoneId,
      zoneName: rule.zoneName,
      type: action.type || 'forward',
      enabled: !!rule.enabled,
      destination: Array.isArray(action.value) ? action.value[0] : action.value,
      lastActivity: getAddressActivity(address)
    };
    existing.count += 1;
    map.set(key, existing);
  });
  state.addresses = Array.from(map.values());
  updateAddressSortAvailability();
  renderAddressList();
}

function renderAddressList() {
  const container = document.getElementById('address-list');
  const empty = document.getElementById('address-empty');
  const search = (document.getElementById('addressSearch').value || '').trim().toLowerCase();
  const sortValue = document.getElementById('addressSort')?.value || 'name-asc';
  let items = state.addresses.filter((item) => !search || item.address.toLowerCase().includes(search));
  items = [...items].sort((a, b) => {
    const nameA = a.address.toLowerCase();
    const nameB = b.address.toLowerCase();
    if (sortValue === 'name-desc') return nameB.localeCompare(nameA);
    if (sortValue === 'newest' || sortValue === 'oldest') {
      const aTime = a.lastActivity || 0;
      const bTime = b.lastActivity || 0;
      if (!aTime && !bTime) {
        return nameA.localeCompare(nameB);
      }
      return sortValue === 'newest' ? bTime - aTime : aTime - bTime;
    }
    return nameA.localeCompare(nameB);
  });
  container.innerHTML = '';
  items.forEach((item, index) => {
    const fullAddress = item.address || '';
    const atIndex = fullAddress.indexOf('@');
    const localPart = atIndex > -1 ? fullAddress.slice(0, atIndex) : fullAddress;
    const domainPart = atIndex > -1 ? fullAddress.slice(atIndex + 1) : '';
    const domainLabel = domainPart ? `@${domainPart}` : '';
    const el = document.createElement('div');
    el.className = `address-item${state.selectedAddress === item.address ? ' active' : ''}`;
    el.classList.add('list-item');
    el.style.animationDelay = `${Math.min(index, 8) * 40}ms`;
    el.dataset.address = item.address;
    el.dataset.id = item.ruleId;
    el.dataset.zone = item.zoneId || '';
    el.innerHTML = `
      <div class="address-info">
        <div class="addr-title" title="${escapeHtml(fullAddress)}">${escapeHtml(localPart || fullAddress)}</div>
        <div class="addr-domain" title="${escapeHtml(domainLabel || fullAddress)}">${escapeHtml(domainLabel || '')}</div>
        <div class="address-meta">
          <span class="address-chip">${escapeHtml(item.type)}</span>
        </div>
      </div>
      <div class="address-actions">
        <button class="mini-btn" data-action="copy" title="Copy email">
          <span class="material-icons">content_copy</span>
        </button>
        <button class="mini-btn" data-action="toggle" title="Toggle">
          <span class="material-icons">${item.enabled ? 'toggle_on' : 'toggle_off'}</span>
        </button>
        <button class="mini-btn" data-action="edit" title="Edit">
          <span class="material-icons">edit</span>
        </button>
        <button class="mini-btn" data-action="delete" title="Delete">
          <span class="material-icons">delete</span>
        </button>
      </div>
    `;
    container.appendChild(el);
  });
  empty.style.display = items.length ? 'none' : 'block';
}

function setSelectedAddress(address) {
  state.selectedAddress = address;
  localStorage.setItem('selectedAddress', address || '');
  renderAddressList();
  loadInbox(0);
}

function updateAddressSortAvailability() {
  const select = document.getElementById('addressSort');
  if (!select) return;
  const hasActivity = hasActivityData();
  Array.from(select.options).forEach((opt) => {
    if (opt.dataset.requiresActivity) {
      opt.disabled = !hasActivity;
    }
  });
  if (!hasActivity && (select.value === 'newest' || select.value === 'oldest')) {
    select.value = 'name-asc';
    localStorage.setItem(ADDRESS_SORT_KEY, 'name-asc');
  }
}

async function handleAddressToggle(ruleId, zoneId) {
  const rule = state.ruleMap.get(getRuleMapKey(ruleId, zoneId));
  if (!rule) return;
  const willEnable = !rule.enabled;
  try {
    await api(`/api/rules/${encodeURIComponent(ruleId)}`, {
      method: 'PUT',
      body: JSON.stringify({ enabled: willEnable, zoneId: zoneId || null })
    });
    showNotification(willEnable ? 'Rule activated' : 'Rule deactivated', 'success');
    loadRules();
  } catch (e) {
    showNotification('Toggle failed: ' + e.message, 'error');
  }
}

async function handleAddressDelete(ruleId, zoneId) {
  if (!confirm('Delete this rule?')) return;
  try {
    await api(`/api/rules/${encodeURIComponent(ruleId)}?zoneId=${encodeURIComponent(zoneId || '')}`, { method: 'DELETE' });
    showNotification('Rule deleted', 'success');
    loadRules();
  } catch (e) {
    showNotification('Delete failed: ' + e.message, 'error');
  }
}

async function copyToClipboard(value, successMessage, errorMessage) {
  if (!value) return;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(value);
    } else {
      const temp = document.createElement('textarea');
      temp.value = value;
      temp.style.position = 'fixed';
      temp.style.opacity = '0';
      document.body.appendChild(temp);
      temp.select();
      document.execCommand('copy');
      temp.remove();
    }
    showNotification(successMessage, 'success');
  } catch (e) {
    showNotification(errorMessage, 'error');
  }
}

async function copyAddress(address) {
  return copyToClipboard(address, 'Email disalin', 'Gagal menyalin email');
}
function showAddRuleDialog() {
  state.editingRuleId = null;
  state.editingRuleZoneId = null;
  document.getElementById('modalTitle').textContent = 'Add New Rule';
  document.getElementById('saveBtn').innerHTML = '<span class="material-icons">save</span> Save Rule';
  document.getElementById('ruleForm').reset();
  const workerSelect = document.getElementById('workerSelect');
  if (workerSelect) {
    workerSelect.classList.add('is-hidden');
    workerSelect.disabled = true;
  }
  updateDomainSelect();
  updateFromPreview();
  updateRuleTypeUI();
  validateRuleForm();
  document.getElementById('ruleModal').classList.add('active');
}

function populateEditRule(rule) {
  const address = rule.matchers && rule.matchers[0] && rule.matchers[0].value;
  if (!address) return;
  const parts = address.split('@');
  const localPart = parts[0] || '';
  const domainName = parts[1] || '';

  state.editingRuleId = rule.id;
  state.editingRuleZoneId = rule.zoneId || null;
  document.getElementById('modalTitle').textContent = 'Edit Rule';
  document.getElementById('saveBtn').innerHTML = '<span class="material-icons">save</span> Update Rule';
  document.getElementById('fromLocalPart').value = localPart;

  updateDomainSelect(rule.zoneId || null);
  if (domainName && !state.domains.find((d) => d.name === domainName)) {
    const select = document.getElementById('fromDomain');
    const opt = document.createElement('option');
    opt.value = rule.zoneId || '';
    opt.textContent = domainName;
    select.appendChild(opt);
    select.value = rule.zoneId || '';
  }

  const action = rule.actions && rule.actions[0] ? rule.actions[0] : {};
  document.getElementById('ruleType').value = action.type || 'forward';
  const dest = Array.isArray(action.value) ? action.value[0] : action.value || '';
  document.getElementById('toEmail').value = dest;
  if ((action.type || '') === 'worker') {
    loadWorkers().then(() => updateWorkerSelect(dest));
  }
  updateFromPreview();
  updateRuleTypeUI();
  validateRuleForm();
  document.getElementById('ruleModal').classList.add('active');
}

function closeRuleModal() {
  document.getElementById('ruleModal').classList.remove('active');
}

function updateFromPreview() {
  const localPart = document.getElementById('fromLocalPart').value.trim();
  const domainSelect = document.getElementById('fromDomain');
  const selectedDomain = domainSelect && !domainSelect.disabled && domainSelect.options.length
    ? domainSelect.options[domainSelect.selectedIndex].textContent
    : '';
  const preview = document.getElementById('fromPreview');
  if (!preview) return;
  const result = localPart && selectedDomain ? `${localPart}@${selectedDomain}` : 'nama@domain.com';
  preview.textContent = `Hasil: ${result}`;
}

function updateRuleTypeUI() {
  const type = document.getElementById('ruleType').value;
  const toField = document.getElementById('toEmail');
  const workerSelect = document.getElementById('workerSelect');
  const toLabel = document.getElementById('toLabel');
  const toHelp = document.getElementById('toHelp');
  const isDrop = type === 'drop';
  if (isDrop) {
    toField.value = '';
    toField.required = false;
    toField.disabled = true;
    toField.classList.remove('is-hidden');
    if (workerSelect) {
      workerSelect.classList.add('is-hidden');
      workerSelect.disabled = true;
    }
    toLabel.textContent = 'Tujuan';
    toHelp.textContent = 'Tidak perlu tujuan untuk drop.';
    return;
  }

  if (type === 'worker') {
    if (!state.workersLoaded) {
      updateWorkerSelect();
      loadWorkers();
    }
    const workerFallback = state.workersLoaded && (state.workersError || !state.workers.length);
    toLabel.textContent = 'Worker';
    if (workerFallback) {
      toField.disabled = false;
      toField.required = true;
      toField.classList.remove('is-hidden');
      toField.placeholder = 'nama-worker';
      toHelp.textContent = state.workersError
        ? 'Gagal memuat worker. Isi manual jika diperlukan.'
        : 'Tidak ada worker. Isi manual jika diperlukan.';
      if (workerSelect) {
        workerSelect.classList.add('is-hidden');
        workerSelect.disabled = true;
      }
    } else {
      toField.value = '';
      toField.required = false;
      toField.disabled = true;
      toField.classList.add('is-hidden');
      toHelp.textContent = 'Pilih worker untuk menerima pesan.';
      if (workerSelect) {
        workerSelect.classList.remove('is-hidden');
        updateWorkerSelect();
      }
    }
    return;
  }

  toField.disabled = false;
  toField.required = true;
  toField.placeholder = 'admin@company.com';
  toField.classList.remove('is-hidden');
  if (workerSelect) {
    workerSelect.classList.add('is-hidden');
    workerSelect.disabled = true;
  }
  toLabel.textContent = 'Tujuan';
  toHelp.textContent = 'Tujuan email penerima.';
}

function validateLocalPart(value) {
  if (!value) return 'Nama email wajib diisi.';
  if (value.includes('@')) return 'Jangan gunakan @ pada nama email.';
  if (/\s/.test(value)) return 'Tidak boleh ada spasi.';
  if (!/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(value)) return 'Format nama email tidak valid.';
  return '';
}

function validateRuleForm() {
  const localPart = document.getElementById('fromLocalPart').value.trim();
  const type = document.getElementById('ruleType').value;
  const toValue = document.getElementById('toEmail').value.trim();
  const workerSelect = document.getElementById('workerSelect');
  const fromError = document.getElementById('fromError');
  const toError = document.getElementById('toError');
  const saveBtn = document.getElementById('saveBtn');
  const domainSelect = document.getElementById('fromDomain');

  const localError = validateLocalPart(localPart);
  const domainError = domainSelect && domainSelect.disabled ? 'Daftar domain tidak tersedia.' : '';
  fromError.textContent = localError || domainError;

  let toErr = '';
  if (type === 'worker') {
    const usingSelect = workerSelect && !workerSelect.classList.contains('is-hidden');
    if (usingSelect) {
      if (!workerSelect.value || workerSelect.disabled) toErr = 'Worker wajib dipilih.';
    } else if (!toValue) {
      toErr = 'Worker wajib diisi.';
    }
  } else if (type !== 'drop' && !toValue) {
    toErr = 'Tujuan wajib diisi.';
  }
  toError.textContent = toErr;

  const valid = !localError && !domainError && !toErr;
  saveBtn.disabled = !valid;
  return valid;
}

function buildFromEmail() {
  const localPart = document.getElementById('fromLocalPart').value.trim();
  const domainSelect = document.getElementById('fromDomain');
  const domainName = domainSelect && domainSelect.options.length ? domainSelect.options[domainSelect.selectedIndex].textContent : '';
  if (!domainName) return localPart;
  return `${localPart}@${domainName}`;
}

function getDestinationValue(type) {
  const toField = document.getElementById('toEmail');
  const workerSelect = document.getElementById('workerSelect');
  if (type === 'worker') {
    if (workerSelect && !workerSelect.classList.contains('is-hidden') && workerSelect.value) {
      return workerSelect.value.trim();
    }
    return (toField && toField.value ? toField.value.trim() : '');
  }
  return toField && toField.value ? toField.value.trim() : '';
}

async function saveRule(event) {
  event.preventDefault();
  if (!validateRuleForm()) return;
  const fromEmail = buildFromEmail();
  const ruleType = document.getElementById('ruleType').value;
  const toEmail = getDestinationValue(ruleType);
  const zoneId = document.getElementById('fromDomain').value || state.editingRuleZoneId;

  try {
    if (state.editingRuleId) {
      await api(`/api/rules/${encodeURIComponent(state.editingRuleId)}`, {
        method: 'PUT',
        body: JSON.stringify({ customEmail: fromEmail, destinationId: toEmail, type: ruleType, zoneId: zoneId || null })
      });
      showNotification('Rule updated successfully!', 'success');
    } else {
      await api('/api/rules', {
        method: 'POST',
        body: JSON.stringify({ customEmail: fromEmail, destinationIdManual: toEmail, type: ruleType, zoneId: zoneId || null })
      });
      showNotification('Rule created successfully!', 'success');
    }
    closeRuleModal();
    loadRules();
  } catch (e) {
    showNotification('Save failed: ' + e.message, 'error');
  }
}

async function loadInbox(page = 0) {
  const list = document.getElementById('inbox-list');
  const empty = document.getElementById('inbox-empty');
  const subtitle = document.getElementById('inbox-subtitle');
  if (!state.selectedAddress) {
    list.innerHTML = '';
    empty.style.display = 'block';
    empty.textContent = 'Select an address to view messages.';
    subtitle.textContent = 'Select an address to load messages';
    return;
  }
  empty.style.display = 'none';
  list.innerHTML = '<div class="loading">Loading messages...</div>';
  try {
    const emails = await api(`/api/inbox?limit=${state.inboxLimit}&offset=${page * state.inboxLimit}&recipient=${encodeURIComponent(state.selectedAddress)}`);
    state.inbox = emails;
    state.inboxPage = page;
    if (emails && emails.length) {
      const latest = Math.max(...emails.map((email) => new Date(email.created_at || 0).getTime()));
      if (Number.isFinite(latest) && latest > 0) {
        setAddressActivity(state.selectedAddress, latest);
        state.addresses.forEach((item) => {
          if (item.address.toLowerCase() === state.selectedAddress.toLowerCase()) {
            item.lastActivity = latest;
          }
        });
        updateAddressSortAvailability();
        renderAddressList();
      }
    }
    renderInbox();
    document.getElementById('btn-inbox-prev').disabled = state.inboxPage === 0;
    document.getElementById('btn-inbox-next').disabled = emails.length < state.inboxLimit;
    subtitle.textContent = `Viewing ${state.selectedAddress}`;
  } catch (e) {
    list.innerHTML = '';
    const errorEl = document.createElement('div');
    errorEl.className = 'loading';
    errorEl.textContent = `Failed to load inbox: ${e.message}`;
    list.appendChild(errorEl);
  }
}

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function cleanLocalPart(localPart) {
  if (!localPart) return '';
  let cleaned = localPart.replace(/\+.*$/, '');
  const stripped = cleaned.replace(
    /^(bounce|bounces|noreply|no-reply|donotreply|do-not-reply|mailer-daemon|postmaster|notifications?)[._+-]*/i,
    ''
  );
  cleaned = (stripped || cleaned).trim();
  return cleaned;
}

function formatLabel(value) {
  const normalized = String(value || '').replace(/[._-]+/g, ' ').replace(/\s+/g, ' ').trim();
  if (!normalized) return '';
  return normalized.replace(/\b\w/g, (char) => char.toUpperCase());
}

function getSenderInfo(rawSender) {
  const sender = String(rawSender || '').trim();
  let email = '';
  let name = '';
  const match = sender.match(/^(.*)<([^>]+@[^>]+)>$/);
  if (match) {
    name = match[1].replace(/"/g, '').trim();
    email = match[2].trim();
  } else if (sender.includes('@')) {
    email = sender;
  } else {
    name = sender;
  }

  const domain = email.includes('@') ? email.split('@')[1].trim() : '';
  const localPart = email.includes('@') ? email.split('@')[0].trim() : '';
  const cleanedLocal = cleanLocalPart(localPart);
  const fallbackLabel = cleanedLocal || localPart || '';
  const label = formatLabel(name || fallbackLabel || email || sender || 'Unknown');

  return {
    label: label || 'Unknown',
    email,
    domain: domain || ''
  };
}

function renderInbox() {
  const list = document.getElementById('inbox-list');
  const empty = document.getElementById('inbox-empty');
  const search = (document.getElementById('inboxSearch').value || '').trim().toLowerCase();
  const filtered = state.inbox.filter((email) => {
    if (!search) return true;
    return `${email.subject || ''} ${email.sender || ''}`.toLowerCase().includes(search);
  });
  const sortValue = document.getElementById('inboxSort')?.value || 'newest';
  const sorted = [...filtered].sort((a, b) => {
    const aTime = new Date(a.created_at || 0).getTime();
    const bTime = new Date(b.created_at || 0).getTime();
    if (sortValue === 'oldest') return aTime - bTime;
    if (sortValue === 'az') {
      const nameA = (getSenderInfo(a.sender).label || '').toLowerCase();
      const nameB = (getSenderInfo(b.sender).label || '').toLowerCase();
      return nameA.localeCompare(nameB, undefined, { sensitivity: 'base' });
    }
    return bTime - aTime;
  });
  list.innerHTML = '';
  if (!sorted.length) {
    empty.style.display = 'block';
    empty.textContent = 'No messages yet.';
    return;
  }
  empty.style.display = 'none';
  sorted.forEach((email, index) => {
    const senderInfo = getSenderInfo(email.sender);
    const displayName = senderInfo.label || 'Unknown sender';
    const fromEmail = senderInfo.email || email.sender || 'Unknown';
    const domain = senderInfo.domain || (fromEmail.includes('@') ? fromEmail.split('@')[1] : 'unknown');
    const toLabel = state.selectedAddress || '-';
    const el = document.createElement('div');
    el.className = 'inbox-item';
    el.classList.add('list-item');
    el.style.animationDelay = `${Math.min(index, 10) * 30}ms`;
    el.dataset.id = email.id;
    const initial = displayName[0] || (fromEmail[0] || '?');
    const date = new Date(email.created_at).toLocaleString();
    el.innerHTML = `
      <div class="inbox-avatar">${initial.toUpperCase()}</div>
      <div class="inbox-main">
        <div class="inbox-row">
          <div class="inbox-from-name" title="${escapeHtml(displayName)}">${escapeHtml(displayName)}</div>
          <div class="inbox-date">${date}</div>
        </div>
        <div class="inbox-subject" title="${escapeHtml(email.subject || '(No subject)')}">${escapeHtml(email.subject || '(No subject)')}</div>
        <div class="inbox-meta">
          <span class="inbox-domain" title="${escapeHtml(domain)}">${escapeHtml(domain)}</span>
          <span class="inbox-from-email" title="${escapeHtml(fromEmail)}">${escapeHtml(fromEmail)}</span>
          <span class="inbox-to" title="To: ${escapeHtml(toLabel)}">To: ${escapeHtml(toLabel)}</span>
        </div>
      </div>
    `;
    list.appendChild(el);
  });
}

async function openEmail(id) {
  const overlay = document.getElementById('viewerOverlay');
  overlay.classList.add('active');
  try {
    const email = await api(`/api/inbox/${id}`);
    state.currentEmailId = id;
    document.getElementById('viewerSubject').textContent = email.subject || 'No subject';
    document.getElementById('viewerFrom').textContent = `From: ${email.sender || '-'}`;
    document.getElementById('viewerTo').textContent = `To: ${email.recipient || '-'}`;
    document.getElementById('viewerDate').textContent = new Date(email.created_at).toLocaleString();
    state.currentEmailData = email;
    renderEmailBody('html');
  } catch (e) {
    const container = document.getElementById('emailBodyContainer');
    container.innerHTML = '';
    const errorEl = document.createElement('div');
    errorEl.className = 'loading';
    errorEl.textContent = `Error loading email: ${e.message}`;
    container.appendChild(errorEl);
  }
}

function closeEmailViewer() {
  document.getElementById('viewerOverlay').classList.remove('active');
}

function renderEmailBody(type) {
  const container = document.getElementById('emailBodyContainer');
  const btnHtml = document.getElementById('btn-view-html');
  const btnText = document.getElementById('btn-view-text');
  if (type === 'html') {
    btnHtml.classList.add('active');
    btnText.classList.remove('active');
    const iframe = document.createElement('iframe');
    iframe.className = 'email-body-iframe';
    iframe.setAttribute('sandbox', '');
    iframe.setAttribute('referrerpolicy', 'no-referrer');
    iframe.srcdoc = state.currentEmailData?.html_body || '<div style="font-family: sans-serif; padding: 20px;">No HTML content</div>';
    container.innerHTML = '';
    container.appendChild(iframe);
  } else {
    btnHtml.classList.remove('active');
    btnText.classList.add('active');
    const div = document.createElement('div');
    div.className = 'email-body-text';
    div.textContent = state.currentEmailData?.text_body || '(No text content)';
    container.innerHTML = '';
    container.appendChild(div);
  }
}

async function deleteEmail() {
  if (!state.currentEmailId) return;
  if (!confirm('Delete this email?')) return;
  try {
    await api(`/api/inbox/${state.currentEmailId}`, { method: 'DELETE' });
    showNotification('Email deleted', 'success');
    closeEmailViewer();
    loadInbox(state.inboxPage);
  } catch (e) {
    showNotification('Failed to delete: ' + e.message, 'error');
  }
}

async function handleLogout() {
  try {
    await fetch('/api/logout', { method: 'POST', credentials: 'include' });
  } catch {}
  clearLegacyAuthStorage();
  localStorage.removeItem('selectedAddress');
  state.rules = [];
  state.ruleMap = new Map();
  state.addresses = [];
  state.selectedAddress = null;
  state.inbox = [];
  state.inboxPage = 0;
  state.currentEmailId = null;
  state.currentEmailData = null;

  const addressList = document.getElementById('address-list');
  if (addressList) addressList.innerHTML = '';
  const addressEmpty = document.getElementById('address-empty');
  if (addressEmpty) addressEmpty.style.display = 'block';

  const inboxList = document.getElementById('inbox-list');
  if (inboxList) inboxList.innerHTML = '';
  const inboxEmpty = document.getElementById('inbox-empty');
  if (inboxEmpty) {
    inboxEmpty.style.display = 'block';
    inboxEmpty.textContent = 'Select an address to view messages.';
  }
  const subtitle = document.getElementById('inbox-subtitle');
  if (subtitle) subtitle.textContent = 'Select an address to load messages';

  closeEmailViewer();
  setLoginDisabled(false);
  setLoginVisible(true);
}

// Element SDK configuration (optional)
async function onConfigChange(config) {
  const panelTitle = config.panel_title || defaultConfig.panel_title;
  const welcomeMessage = config.welcome_message || defaultConfig.welcome_message;
  const titleEl = document.getElementById('panel-title');
  const subtitleEl = document.getElementById('welcome-message');
  if (titleEl) titleEl.textContent = panelTitle;
  if (subtitleEl) subtitleEl.textContent = welcomeMessage;
}
function mapToCapabilities(_config) { return { recolorables: [], borderables: [], fontEditable: undefined, fontSizeable: undefined }; }
function mapToEditPanelValues(config) { return new Map([['panel_title', config.panel_title || defaultConfig.panel_title], ['welcome_message', config.welcome_message || defaultConfig.welcome_message]]); }

document.addEventListener('DOMContentLoaded', async function () {
  loadTheme();
  clearLegacyAuthStorage();

  const themeBtn = document.getElementById('btn-theme-toggle');
  if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

  document.querySelectorAll('#themePresets .chip').forEach((btn) => {
    btn.addEventListener('click', () => applyAccentPreset(btn.dataset.preset));
  });

  const accentApply = document.getElementById('accentApply');
  const accentPicker = document.getElementById('accentPicker');
  const accentHexDisplay = document.getElementById('accentHexDisplay');
  let accentDebounce = null;
  if (accentPicker) {
    accentPicker.addEventListener('input', () => {
      const value = accentPicker.value;
      if (accentHexDisplay) accentHexDisplay.value = value;
      if (accentDebounce) clearTimeout(accentDebounce);
      accentDebounce = setTimeout(() => {
        if (!applyCustomAccent(value)) {
          showNotification('Invalid hex color', 'error');
        }
      }, 250);
    });
  }
  if (accentApply) {
    accentApply.addEventListener('click', () => {
      const value = accentPicker ? accentPicker.value : (accentHexDisplay ? accentHexDisplay.value : '');
      if (!applyCustomAccent(value)) {
        showNotification('Invalid hex color', 'error');
      }
    });
  }

  const sidebarHandle = document.getElementById('sidebarHandle');
  if (sidebarHandle) sidebarHandle.addEventListener('click', toggleSidebar);
  const sidebarOverlay = document.getElementById('sidebarOverlay');
  if (sidebarOverlay) sidebarOverlay.addEventListener('click', () => setSidebarState('collapsed'));
  const savedState = localStorage.getItem(SIDEBAR_STATE_KEY);
  if (savedState === 'open' || savedState === 'collapsed') {
    setSidebarState(savedState);
  } else {
    const legacy = localStorage.getItem('sidebarCollapsed');
    setSidebarState(legacy === '1' ? 'collapsed' : 'open');
  }

  state.addressActivity = loadAddressActivity();

  const loginForm = document.getElementById('loginForm');
  if (loginForm) loginForm.addEventListener('submit', handleAuth);

  const registerBtn = document.getElementById('btn-register-request');
  if (registerBtn) registerBtn.addEventListener('click', requestRegister);

  const authStatus = await fetchAuthStatus();
  if (authStatus) {
    authOptions = {
      token: !!authStatus.accessTokenEnabled,
      tfa: !!authStatus.tfaEnabled,
      password: !!authStatus.passwordEnabled,
      authRequired: !!authStatus.authRequired,
      tokenExpired: !!authStatus.tokenExpired,
      tfaExpired: !!authStatus.tfaExpired,
      registerPending: !!authStatus.registerPending,
      registerExpiresAt: authStatus.registerExpiresAt || null
    };
  }

  if (authOptions.registerPending) {
    setAuthNotice('Register request pending approval in bot.', 'warning');
    startRegisterPolling();
  } else if (authOptions.tokenExpired || authOptions.tfaExpired) {
    setAuthNotice('Login expired. Request a new token from the bot.', 'warning');
  } else if (authOptions.authRequired && !(authOptions.token || authOptions.tfa || authOptions.password)) {
    setAuthNotice('Auth required. Configure ACCESS_TOKEN / TFA / PASSWORD in .env.', 'warning');
  } else {
    setAuthNotice('');
  }

  updateRegisterButton();

  if (authOptions.tokenExpired || authOptions.tfaExpired) {
    clearLegacyAuthStorage();
  }

  const authConfigured = authOptions.token || authOptions.tfa || authOptions.password;

  let defaultMode = authOptions.token ? 'token' : (authOptions.tfa ? 'tfa' : (authOptions.password ? 'password' : 'token'));
  if (authOptions.tfa && (authOptions.tokenExpired || !authOptions.token)) defaultMode = 'tfa';
  if (!isTokenUsable() && !isTfaUsable() && isPasswordUsable()) defaultMode = 'password';
  setAuthMode(defaultMode);
  setLoginDisabled(authOptions.registerPending);

  document.querySelectorAll('.auth-toggle-btn').forEach((btn) => {
    btn.addEventListener('click', () => setAuthMode(btn.dataset.auth));
  });

  const settingsForm = document.getElementById('settingsForm');
  if (settingsForm) {
    settingsForm.addEventListener('submit', saveSettings);
    settingsForm.addEventListener('click', handleSettingsAction);
  }

  const tokenInput = document.getElementById('cfgApiToken');
  if (tokenInput) tokenInput.addEventListener('input', updateTokenToggleVisibility);

  const logoutBtn = document.getElementById('btn-logout');
  if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);

  const checkBtn = document.getElementById('btn-check-status');
  if (checkBtn) checkBtn.addEventListener('click', () => checkApiStatus(checkBtn));

  const addRuleBtn = document.getElementById('btn-add-rule');
  if (addRuleBtn) addRuleBtn.addEventListener('click', showAddRuleDialog);

  document.getElementById('btn-modal-close')?.addEventListener('click', closeRuleModal);
  document.getElementById('btn-cancel')?.addEventListener('click', closeRuleModal);
  document.getElementById('ruleForm')?.addEventListener('submit', saveRule);

  document.getElementById('fromLocalPart')?.addEventListener('input', () => {
    updateFromPreview();
    validateRuleForm();
  });
  document.getElementById('fromDomain')?.addEventListener('change', () => {
    updateFromPreview();
    validateRuleForm();
  });
  document.getElementById('toEmail')?.addEventListener('input', validateRuleForm);
  document.getElementById('workerSelect')?.addEventListener('change', validateRuleForm);
  document.getElementById('ruleType')?.addEventListener('change', () => {
    updateRuleTypeUI();
    validateRuleForm();
  });

  const addressSearch = document.getElementById('addressSearch');
  if (addressSearch) addressSearch.addEventListener('input', renderAddressList);
  const addressSort = document.getElementById('addressSort');
  if (addressSort) {
    const savedSort = localStorage.getItem(ADDRESS_SORT_KEY);
    if (savedSort) addressSort.value = savedSort;
    addressSort.addEventListener('change', () => {
      localStorage.setItem(ADDRESS_SORT_KEY, addressSort.value);
      renderAddressList();
    });
  }

  document.getElementById('address-list')?.addEventListener('click', (e) => {
    const actionBtn = e.target.closest('button[data-action]');
    if (actionBtn) {
      const item = actionBtn.closest('.address-item');
      if (!item) return;
      const ruleId = item.dataset.id;
      const zoneId = item.dataset.zone || null;
      const action = actionBtn.dataset.action;
      if (action === 'copy') {
        copyAddress(item.dataset.address);
        return;
      }
      if (action === 'toggle') return handleAddressToggle(ruleId, zoneId);
      if (action === 'edit') {
        const rule = state.ruleMap.get(getRuleMapKey(ruleId, zoneId));
        if (rule) populateEditRule(rule);
        return;
      }
      if (action === 'delete') return handleAddressDelete(ruleId, zoneId);
      return;
    }
    const item = e.target.closest('.address-item');
    if (!item) return;
    setSelectedAddress(item.dataset.address);
  });

  document.getElementById('btn-refresh-inbox')?.addEventListener('click', () => loadInbox(state.inboxPage));
  document.getElementById('btn-inbox-prev')?.addEventListener('click', () => loadInbox(state.inboxPage - 1));
  document.getElementById('btn-inbox-next')?.addEventListener('click', () => loadInbox(state.inboxPage + 1));
  document.getElementById('inboxSearch')?.addEventListener('input', renderInbox);
  document.getElementById('inboxSort')?.addEventListener('change', renderInbox);

  document.getElementById('inbox-list')?.addEventListener('click', (e) => {
    const item = e.target.closest('.inbox-item');
    if (!item) return;
    openEmail(item.dataset.id);
  });

  document.getElementById('btn-viewer-close')?.addEventListener('click', closeEmailViewer);
  document.getElementById('btn-email-close-action')?.addEventListener('click', closeEmailViewer);
  document.getElementById('btn-view-html')?.addEventListener('click', () => renderEmailBody('html'));
  document.getElementById('btn-view-text')?.addEventListener('click', () => renderEmailBody('text'));
  document.getElementById('btn-email-delete')?.addEventListener('click', deleteEmail);

  await loadSettings();

  if (window.elementSdk) {
    window.elementSdk.init({ defaultConfig, onConfigChange, mapToCapabilities, mapToEditPanelValues });
  }

  if (!authConfigured) {
    if (authOptions.authRequired) {
      setLoginVisible(true);
    } else {
      setLoginVisible(false);
      await loadRules();
    }
  } else if (authOptions.registerPending) {
    setLoginVisible(true);
  } else {
    const sessionOk = await checkSession();
    if (sessionOk) {
      setLoginVisible(false);
      await loadRules();
    } else {
      setLoginVisible(true);
    }
  }

  const storedAddress = localStorage.getItem('selectedAddress');
  if (storedAddress) {
    state.selectedAddress = storedAddress;
    renderAddressList();
    loadInbox(0);
  }
});
