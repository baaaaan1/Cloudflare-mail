// main.js - Glassmorphism mail client UI for Cloudflare Email Panel
// Simplified: Password-only auth, private mode
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
  inboxSummary: {},
  inbox: [],
  inboxPage: 0,
  inboxLimit: 20,
  domains: [],
  domainsLoaded: false,
  domainsLoading: false,
  domainsError: null,
  savingRule: false,
  workers: [],
  workersLoaded: false,
  workersLoading: false,
  workersError: null,
  editingRuleId: null,
  editingRuleZoneId: null,
  currentEmailId: null,
  currentEmailData: null
};

let sessionOk = false;

const accentPresets = {
  ocean: { accent: '#5aa9ff', accent2: '#7fd1ff', accent3: '#3c6fff' },
  purple: { accent: '#9b7bff', accent2: '#c0a0ff', accent3: '#6b4cff' },
  emerald: { accent: '#30c28a', accent2: '#6adbb1', accent3: '#1a8f69' },
  amber: { accent: '#f4a340', accent2: '#ffd089', accent3: '#d97706' }
};

const ADDRESS_SORT_KEY = 'addressSort';
const ADDRESS_ACTIVITY_KEY = 'addressActivity';
const emailNameParts = {
  id: {
    first: ['aditya', 'agung', 'andika', 'bagas', 'bima', 'dewi', 'dimas', 'farhan', 'fajar', 'fitri', 'galih', 'hana', 'indah', 'joko', 'kurnia', 'lina', 'maulana', 'nabila', 'putra', 'rani', 'reza', 'rizky', 'salsa', 'tiara', 'wahyu', 'yusuf'],
    last: ['ananda', 'cahaya', 'hidayat', 'kurniawan', 'maharani', 'maulana', 'nugraha', 'permata', 'pratama', 'putri', 'ramadhan', 'saputra', 'setiawan', 'syahputra', 'wijaya']
  },
  us: {
    first: ['alex', 'amelia', 'ava', 'benjamin', 'charlotte', 'daniel', 'elijah', 'emma', 'ethan', 'harper', 'henry', 'isabella', 'james', 'liam', 'lucas', 'mia', 'noah', 'olivia', 'sophia', 'theodore', 'william', 'zoe'],
    last: ['anderson', 'bennett', 'brown', 'carter', 'cooper', 'davis', 'edwards', 'garcia', 'harris', 'johnson', 'martin', 'miller', 'mitchell', 'roberts', 'smith', 'thompson', 'wilson']
  }
};

function randomItem(items) {
  return items[Math.floor(Math.random() * items.length)];
}

function generateEmailName() {
  const style = document.getElementById('emailNameStyle')?.value === 'us' ? 'us' : 'id';
  const parts = emailNameParts[style];
  const suffix = String(Math.floor(Math.random() * 900) + 100);
  const localPart = `${randomItem(parts.first)}.${randomItem(parts.last)}${suffix}`;
  const input = document.getElementById('fromLocalPart');
  if (!input) return;
  input.value = localPart;
  updateFromPreview();
  validateRuleForm();
  input.focus();
}

async function api(path, opts) {
  const headers = { 'Content-Type': 'application/json' };
  const res = await fetch(path, Object.assign({ headers, credentials: 'include' }, opts));
  if (res.status === 401) {
    sessionOk = false;
    showLogin();
    throw new Error('Unauthorized');
  }
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  return res.json();
}

function showLogin() {
  const modal = document.getElementById('loginModal');
  if (modal) modal.classList.add('active');
  document.body.classList.add('login-active');
  const setupModal = document.getElementById('setupPasswordModal');
  if (setupModal) setupModal.classList.remove('active');
}

function hideLogin() {
  const modal = document.getElementById('loginModal');
  if (modal) modal.classList.remove('active');
  document.body.classList.remove('login-active');
}

function showSetupPassword() {
  hideLogin();
  const modal = document.getElementById('setupPasswordModal');
  if (modal) modal.classList.add('active');
}

function hideSetupPassword() {
  const modal = document.getElementById('setupPasswordModal');
  if (modal) modal.classList.remove('active');
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

function formatRelativeTime(value) {
  const time = value instanceof Date ? value.getTime() : new Date(value || 0).getTime();
  if (!Number.isFinite(time) || time <= 0) return '-';
  const diff = Date.now() - time;
  const abs = Math.abs(diff);
  const units = [
    ['tahun', 365 * 24 * 60 * 60 * 1000],
    ['bulan', 30 * 24 * 60 * 60 * 1000],
    ['hari', 24 * 60 * 60 * 1000],
    ['jam', 60 * 60 * 1000],
    ['menit', 60 * 1000]
  ];
  for (const [label, ms] of units) {
    if (abs >= ms) {
      const amount = Math.max(1, Math.floor(abs / ms));
      return diff >= 0 ? `${amount} ${label} lalu` : `dalam ${amount} ${label}`;
    }
  }
  return 'baru saja';
}

function getRuleTimestamp(rule) {
  const candidates = [rule.created_at, rule.created, rule.created_on, rule.modified_at, rule.modified_on];
  for (const value of candidates) {
    const time = new Date(value || 0).getTime();
    if (Number.isFinite(time) && time > 0) return time;
  }
  return 0;
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
  if (persist) localStorage.setItem('theme', mode);
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
        if (!localStorage.getItem('theme')) applyTheme(event.matches ? 'dark' : 'light', false);
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

async function checkSession() {
  try {
    await api('/api/session');
    sessionOk = true;
    return true;
  } catch {
    sessionOk = false;
    return false;
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

function setSetupNotice(message, tone = 'warning') {
  const notice = document.getElementById('setupNotice');
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

async function handleLogin(event) {
  event.preventDefault();
  const password = document.getElementById('passwordInput').value;
  if (!password) {
    showNotification('Password required', 'error');
    return;
  }
  try {
    await api('/api/login', { method: 'POST', body: JSON.stringify({ password }) });
    hideLogin();
    sessionOk = true;
    await loadRules();
  } catch (e) {
    showNotification('Login failed: ' + e.message, 'error');
  }
}

async function handleSetupPassword(event) {
  event.preventDefault();
  const password = document.getElementById('newPassword').value;
  const confirm = document.getElementById('confirmPassword').value;
  if (password !== confirm) {
    setSetupNotice('Password tidak cocok!', 'error');
    return;
  }
  if (password.length < 8) {
    setSetupNotice('Password minimal 8 karakter', 'error');
    return;
  }
  setSetupNotice('');
  try {
    const res = await fetch('/api/setup-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Gagal set password');
    showNotification(data.message || 'Password berhasil diset!', 'success');
    hideSetupPassword();
    showLogin();
  } catch (e) {
    setSetupNotice(e.message, 'error');
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

async function runDiagnostics(buttonEl) {
  const button = buttonEl;
  const resultEl = document.getElementById('diagnosticsResult');
  const originalContent = button.textContent;
  button.textContent = 'Running...';
  button.disabled = true;
  try {
    const data = await api('/api/diagnostics');
    if (!resultEl) return;
    resultEl.classList.remove('is-hidden');
    let html = `<div class="diag-summary ${data.ok ? 'ok' : 'fail'}">${data.ok ? 'All checks passed' : 'Some checks failed'}</div>`;
    html += '<ul class="diag-list">';
    (data.checks || []).forEach((c) => {
      html += `<li class="diag-item ${c.ok ? 'ok' : 'fail'}">`;
      html += `<span class="diag-name">${escapeHtml(c.name)}</span>`;
      html += `<span class="diag-detail">${escapeHtml(c.detail)}</span>`;
      if (!c.ok && c.hint) html += `<span class="diag-hint">${escapeHtml(c.hint)}</span>`;
      html += '</li>';
    });
    html += '</ul>';
    resultEl.innerHTML = html;
  } catch (e) {
    showNotification('Diagnostics failed: ' + e.message, 'error');
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
  state.domainsLoading = true;
  state.domainsError = null;
  updateDomainSelect();
  try {
    const domains = await api('/api/domains');
    state.domains = Array.isArray(domains) ? domains : [];
    if (!Array.isArray(domains)) {
      state.domainsError = 'Format daftar domain tidak valid';
    }
  } catch (e) {
    state.domains = [];
    state.domainsError = e.message || 'Gagal memuat domain';
  }
  state.domainsLoading = false;
  state.domainsLoaded = true;
  updateDomainSelect();
  return state.domains;
}

async function loadWorkers(force = false) {
  if (state.workersLoaded && !force) return state.workers;
  if (state.workersLoading) return state.workers;
  state.workersLoading = true;
  state.workersError = null;
  updateWorkerSelect();
  try {
    const workers = await api('/api/workers');
    state.workers = Array.isArray(workers) ? workers : [];
    state.workersError = null;
    if (!Array.isArray(workers)) state.workersError = 'Format daftar worker tidak valid';
  } catch (e) {
    state.workers = [];
    state.workersError = e.message || 'Gagal memuat worker';
  }
  state.workersLoading = false;
  state.workersLoaded = true;
  updateWorkerSelect();
  if (document.getElementById('ruleType')?.value === 'worker') {
    updateRuleTypeUI();
    validateRuleForm();
  }
  return state.workers;
}

function updateWorkerSelect(selectedName = null) {
  const select = document.getElementById('workerSelect');
  if (!select) return;
  select.innerHTML = '';
  if (state.workersLoading) {
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'Memuat worker...';
    select.appendChild(opt);
    select.disabled = true;
    return;
  }
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
  if (state.domainsLoading) {
    select.disabled = true;
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'Memuat domain...';
    select.appendChild(opt);
    return;
  }
  if (state.domainsError) {
    select.disabled = true;
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'Gagal memuat domain';
    select.appendChild(opt);
    return;
  }
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
    if (!domain || !domain.id || !domain.name) return;
    const opt = document.createElement('option');
    opt.value = domain.id;
    opt.textContent = domain.name;
    opt.dataset.name = domain.name;
    select.appendChild(opt);
  });
  if (!select.options.length) {
    select.disabled = true;
    const opt = document.createElement('option');
    opt.value = '';
    opt.textContent = 'Domain list unavailable';
    select.appendChild(opt);
    return;
  }
  if (selectedId && Array.from(select.options).some((opt) => opt.value === selectedId)) {
    select.value = selectedId;
  }
}

function getSelectedDomain() {
  const select = document.getElementById('fromDomain');
  if (!select || select.disabled || !select.value) return null;
  const option = select.options[select.selectedIndex];
  const id = select.value.trim();
  const name = (option?.dataset?.name || option?.textContent || '').trim();
  if (!id || !name) return null;
  return { id, name };
}

function getDomainValidationError() {
  if (state.domainsLoading) return 'Daftar domain sedang dimuat.';
  if (state.domainsError) return 'Gagal memuat domain.';
  if (!state.domains.length) return 'Daftar domain kosong.';
  if (!getSelectedDomain()) return 'Pilih domain yang valid.';
  return '';
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
          .catch((err) => ({ status: 'error', domain, data: [], error: err.message }))
      );
      const results = await Promise.all(requests);
      results.forEach((result) => {
        if (result.status === 'ok') {
          result.data.forEach((rule) => {
            rule.zoneId = result.domain.id;
            rule.zoneName = result.domain.name;
            rules.push(rule);
          });
        } else {
          // Rule access may be unavailable; keep the login UI free of API permission messages.
        }
      });
      setAuthNotice('');
    } else {
      try {
        const data = await api('/api/rules');
        rules = data.map((rule) => ({ ...rule, zoneId: null, zoneName: '' }));
        setAuthNotice('');
      } catch (err) {
        setAuthNotice('');
      }
    }
    state.rules = rules;
    state.ruleMap = new Map();
    rules.forEach((rule) => {
      state.ruleMap.set(getRuleMapKey(rule.id, rule.zoneId), rule);
    });
    await loadInboxSummary();
    buildAddressList();
  } catch (e) {
    showNotification('Load rules failed: ' + e.message, 'error');
  }
}

async function loadInboxSummary() {
  try {
    const rows = await api('/api/inbox/summary');
    const summary = {};
    (Array.isArray(rows) ? rows : []).forEach((row) => {
      const recipient = String(row.recipient || '').trim().toLowerCase();
      if (!recipient) return;
      const latest = new Date(row.latest_at || 0).getTime();
      const first = new Date(row.first_at || 0).getTime();
      summary[recipient] = {
        latestAt: Number.isFinite(latest) ? latest : 0,
        firstAt: Number.isFinite(first) ? first : 0,
        total: Number(row.total || 0)
      };
      if (Number.isFinite(latest) && latest > 0) setAddressActivity(recipient, latest);
    });
    state.inboxSummary = summary;
  } catch {
    state.inboxSummary = {};
  }
}

function buildAddressList() {
  const map = new Map();
  state.rules.forEach((rule) => {
    const address = rule.matchers && rule.matchers[0] && rule.matchers[0].value;
    if (!address) return;
    const key = address.toLowerCase();
    const action = rule.actions && rule.actions[0] ? rule.actions[0] : {};
    const summary = state.inboxSummary[key] || {};
    const createdAt = getRuleTimestamp(rule);
    const existing = map.get(key) || {
      address,
      count: 0,
      ruleId: rule.id,
      zoneId: rule.zoneId,
      zoneName: rule.zoneName,
      type: action.type || 'forward',
      enabled: !!rule.enabled,
      destination: Array.isArray(action.value) ? action.value[0] : action.value,
      lastActivity: summary.latestAt || getAddressActivity(address),
      firstActivity: summary.firstAt || 0,
      messageCount: summary.total || 0,
      createdAt
    };
    existing.count += 1;
    existing.lastActivity = Math.max(existing.lastActivity || 0, summary.latestAt || getAddressActivity(address));
    existing.messageCount = Math.max(existing.messageCount || 0, summary.total || 0);
    existing.createdAt = existing.createdAt ? Math.min(existing.createdAt, createdAt || existing.createdAt) : createdAt;
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
  let items = state.addresses.filter((item) => {
    if (!search) return true;
    return [item.address, item.zoneName, item.type, item.destination]
      .filter(Boolean)
      .join(' ')
      .toLowerCase()
      .includes(search);
  });
  items = [...items].sort((a, b) => {
    const nameA = a.address.toLowerCase();
    const nameB = b.address.toLowerCase();
    if (sortValue === 'name-desc') return nameB.localeCompare(nameA);
    if (sortValue === 'message-newest' || sortValue === 'message-oldest') {
      const aTime = a.lastActivity || 0;
      const bTime = b.lastActivity || 0;
      if (!aTime && !bTime) return nameA.localeCompare(nameB);
      if (!aTime) return 1;
      if (!bTime) return -1;
      return sortValue === 'message-newest' ? bTime - aTime : aTime - bTime;
    }
    if (sortValue === 'created-newest' || sortValue === 'created-oldest') {
      // Use createdAt if available, otherwise fallback to lastActivity
      const aTime = a.createdAt || a.lastActivity || 0;
      const bTime = b.createdAt || b.lastActivity || 0;
      if (!aTime && !bTime) return nameA.localeCompare(nameB);
      if (!aTime) return 1;
      if (!bTime) return -1;
      return sortValue === 'created-newest' ? bTime - aTime : aTime - bTime;
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
    const lastLabel = item.lastActivity ? formatRelativeTime(item.lastActivity) : '-';
    const createdLabel = item.createdAt ? formatRelativeTime(item.createdAt) : '-';
    const destinationLabel = item.destination ? String(item.destination) : '-';
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
          <span class="address-chip type-${escapeHtml(item.type)}">${escapeHtml(item.type)}</span>
          <span class="address-chip ${item.enabled ? 'ok' : 'muted'}">${item.enabled ? 'aktif' : 'nonaktif'}</span>
          <span>${item.messageCount || 0} pesan</span>
        </div>
        <div class="address-stats">
          <span title="Pesan terakhir"><span class="material-icons">schedule</span>${escapeHtml(lastLabel)}</span>
          <span title="Email dibuat"><span class="material-icons">add_circle</span>${escapeHtml(createdLabel)}</span>
        </div>
        <div class="address-destination" title="Tujuan: ${escapeHtml(destinationLabel)}">Tujuan: ${escapeHtml(destinationLabel)}</div>
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
  const hasActivity = state.addresses.some((item) => Number(item.lastActivity) > 0);
  Array.from(select.options).forEach((opt) => {
    if (opt.dataset.requiresActivity) opt.disabled = !hasActivity;
  });
  // Only reset message sort if no activity data
  if (!hasActivity && (select.value === 'message-newest' || select.value === 'message-oldest')) {
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

async function showAddRuleDialog() {
  state.editingRuleId = null;
  state.editingRuleZoneId = null;
  state.savingRule = false;
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
  if (!state.domains.length || state.domainsError) {
    loadDomains(true).then(() => {
      updateFromPreview();
      validateRuleForm();
      if (state.domainsError) {
        showNotification('Gagal memuat domain: ' + state.domainsError, 'error');
      }
    });
  }
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
  const selectedDomain = getSelectedDomain()?.name || '';
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
    if (workerSelect) { workerSelect.classList.add('is-hidden'); workerSelect.disabled = true; }
    toLabel.textContent = 'Tujuan';
    toHelp.textContent = 'Tidak perlu tujuan untuk drop.';
    return;
  }
  if (type === 'worker') {
    toLabel.textContent = 'Worker';
    if (!state.workersLoaded && !state.workersLoading) loadWorkers();
    if (state.workersLoading || !state.workersLoaded) {
      toField.value = '';
      toField.required = false;
      toField.disabled = true;
      toField.classList.add('is-hidden');
      toHelp.textContent = 'Memuat daftar worker...';
      if (workerSelect) {
        workerSelect.classList.remove('is-hidden');
        updateWorkerSelect();
      }
      return;
    }
    const workerFallback = !!state.workersError || !state.workers.length;
    if (workerFallback) {
      toField.disabled = false;
      toField.required = true;
      toField.classList.remove('is-hidden');
      toField.placeholder = 'nama-worker';
      toHelp.textContent = state.workersError ? 'Gagal memuat worker. Isi manual jika diperlukan.' : 'Tidak ada worker. Isi manual jika diperlukan.';
      if (workerSelect) { workerSelect.classList.add('is-hidden'); workerSelect.disabled = true; }
    } else {
      toField.value = '';
      toField.required = false;
      toField.disabled = true;
      toField.classList.add('is-hidden');
      toHelp.textContent = 'Pilih worker untuk menerima pesan.';
      if (workerSelect) { workerSelect.classList.remove('is-hidden'); updateWorkerSelect(); }
    }
    return;
  }
  toField.disabled = false;
  toField.required = true;
  toField.placeholder = 'admin@company.com';
  toField.classList.remove('is-hidden');
  toField.value = type === 'forward' ? toField.value : '';
  if (workerSelect) { workerSelect.classList.add('is-hidden'); workerSelect.disabled = true; }
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
  const localError = validateLocalPart(localPart);
  const domainError = getDomainValidationError();
  fromError.textContent = localError || domainError;
  let toErr = '';
  if (!['forward', 'drop', 'worker'].includes(type)) toErr = 'Tipe rule tidak valid.';
  if (type === 'worker') {
    const usingSelect = workerSelect && !workerSelect.classList.contains('is-hidden');
    if (state.workersLoading || !state.workersLoaded) toErr = 'Worker sedang dimuat.';
    else if (usingSelect) { if (!workerSelect.value || workerSelect.disabled) toErr = 'Worker wajib dipilih.'; }
    else if (!toValue) toErr = 'Worker wajib diisi.';
  } else if (type === 'forward') {
    if (!toValue) toErr = 'Tujuan wajib diisi.';
    else if (!/^\S+@\S+\.\S+$/.test(toValue)) toErr = 'Format email tujuan tidak valid.';
  }
  toError.textContent = toErr;
  const valid = !state.savingRule && !localError && !domainError && !toErr;
  saveBtn.disabled = !valid;
  return valid;
}

function buildFromEmail() {
  const localPart = document.getElementById('fromLocalPart').value.trim();
  const domainName = getSelectedDomain()?.name || '';
  return domainName ? `${localPart}@${domainName}` : localPart;
}

function getDestinationValue(type) {
  const toField = document.getElementById('toEmail');
  const workerSelect = document.getElementById('workerSelect');
  if (type === 'worker') {
    if (workerSelect && !workerSelect.classList.contains('is-hidden') && workerSelect.value) return workerSelect.value.trim();
    return (toField && toField.value ? toField.value.trim() : '');
  }
  return toField && toField.value ? toField.value.trim() : '';
}

async function saveRule(event) {
  event.preventDefault();
  if (state.savingRule) return;
  if (!validateRuleForm()) return;
  const selectedDomain = getSelectedDomain();
  if (!selectedDomain) {
    validateRuleForm();
    showNotification('Pilih domain yang valid terlebih dahulu.', 'error');
    return;
  }
  const fromEmail = buildFromEmail();
  const ruleType = document.getElementById('ruleType').value;
  const toEmail = getDestinationValue(ruleType);
  const zoneId = selectedDomain.id || state.editingRuleZoneId;
  const saveBtn = document.getElementById('saveBtn');
  const originalSaveHtml = saveBtn.innerHTML;
  state.savingRule = true;
  saveBtn.disabled = true;
  saveBtn.innerHTML = '<span class="material-icons">hourglass_empty</span> Saving...';
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
  } finally {
    state.savingRule = false;
    saveBtn.innerHTML = originalSaveHtml;
    validateRuleForm();
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
    .replace(/&/g, '&')
    .replace(/</g, '<')
    .replace(/>/g, '>')
    .replace(/"/g, '"')
    .replace(/'/g, '&#39;');
}

function cleanLocalPart(localPart) {
  if (!localPart) return '';
  let cleaned = localPart.replace(/\+.*$/, '');
  const stripped = cleaned.replace(/^(bounce|bounces|noreply|no-reply|donotreply|do-not-reply|mailer-daemon|postmaster|notifications?)[._+-]*/i, '');
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
  if (match) { name = match[1].replace(/"/g, '').trim(); email = match[2].trim(); }
  else if (sender.includes('@')) email = sender;
  else name = sender;
  const domain = email.includes('@') ? email.split('@')[1].trim() : '';
  const localPart = email.includes('@') ? email.split('@')[0].trim() : '';
  const cleanedLocal = cleanLocalPart(localPart);
  const fallbackLabel = cleanedLocal || localPart || '';
  const label = formatLabel(name || fallbackLabel || email || sender || 'Unknown');
  return { label: label || 'Unknown', email, domain: domain || '' };
}

function renderInbox() {
  const list = document.getElementById('inbox-list');
  const empty = document.getElementById('inbox-empty');
  const search = (document.getElementById('inboxSearch').value || '').trim().toLowerCase();
  const filtered = state.inbox.filter((email) => {
    if (!search) return true;
    return `${email.subject || ''} ${email.sender || ''} ${email.recipient || ''}`.toLowerCase().includes(search);
  });
  const sortValue = document.getElementById('inboxSort')?.value || 'newest';
  const sorted = [...filtered].sort((a, b) => {
    const aTime = new Date(a.created_at || 0).getTime();
    const bTime = new Date(b.created_at || 0).getTime();
    if (sortValue === 'oldest') return aTime - bTime;
    if (sortValue === 'sender-az' || sortValue === 'sender-za' || sortValue === 'az') {
      const nameA = (getSenderInfo(a.sender).label || '').toLowerCase();
      const nameB = (getSenderInfo(b.sender).label || '').toLowerCase();
      return (sortValue === 'sender-za')
        ? nameB.localeCompare(nameA, undefined, { sensitivity: 'base' })
        : nameA.localeCompare(nameB, undefined, { sensitivity: 'base' });
    }
    if (sortValue === 'recipient-az' || sortValue === 'recipient-za') {
      const recA = String(a.recipient || '').toLowerCase();
      const recB = String(b.recipient || '').toLowerCase();
      return sortValue === 'recipient-az'
        ? recA.localeCompare(recB, undefined, { sensitivity: 'base' })
        : recB.localeCompare(recA, undefined, { sensitivity: 'base' });
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
    const toLabel = email.recipient || state.selectedAddress || '-';
    const el = document.createElement('div');
    el.className = 'inbox-item list-item';
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
  try { await fetch('/api/logout', { method: 'POST', credentials: 'include' }); } catch {}
  localStorage.removeItem('selectedAddress');
  state.rules = [];
  state.ruleMap = new Map();
  state.addresses = [];
  state.selectedAddress = null;
  state.inbox = [];
  state.inboxPage = 0;
  state.currentEmailId = null;
  state.currentEmailData = null;
  sessionOk = false;
  const addressList = document.getElementById('address-list');
  if (addressList) addressList.innerHTML = '';
  const addressEmpty = document.getElementById('address-empty');
  if (addressEmpty) addressEmpty.style.display = 'block';
  const inboxList = document.getElementById('inbox-list');
  if (inboxList) inboxList.innerHTML = '';
  const inboxEmpty = document.getElementById('inbox-empty');
  if (inboxEmpty) { inboxEmpty.style.display = 'block'; inboxEmpty.textContent = 'Select an address to view messages.'; }
  const subtitle = document.getElementById('inbox-subtitle');
  if (subtitle) subtitle.textContent = 'Select an address to load messages';
  closeEmailViewer();
  showLogin();
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
      accentDebounce = setTimeout(() => { if (!applyCustomAccent(value)) showNotification('Invalid hex color', 'error'); }, 250);
    });
  }
  if (accentApply) {
    accentApply.addEventListener('click', () => {
      const value = accentPicker ? accentPicker.value : (accentHexDisplay ? accentHexDisplay.value : '');
      if (!applyCustomAccent(value)) showNotification('Invalid hex color', 'error');
    });
  }

  const sidebarHandle = document.getElementById('sidebarHandle');
  if (sidebarHandle) sidebarHandle.addEventListener('click', toggleSidebar);
  const sidebarOverlay = document.getElementById('sidebarOverlay');
  if (sidebarOverlay) sidebarOverlay.addEventListener('click', () => setSidebarState('collapsed'));
  const savedState = localStorage.getItem(SIDEBAR_STATE_KEY);
  if (savedState === 'open' || savedState === 'collapsed') setSidebarState(savedState);
  else { const legacy = localStorage.getItem('sidebarCollapsed'); setSidebarState(legacy === '1' ? 'collapsed' : 'open'); }

  state.addressActivity = loadAddressActivity();

  const loginForm = document.getElementById('loginForm');
  if (loginForm) loginForm.addEventListener('submit', handleLogin);

  const setupPasswordForm = document.getElementById('setupPasswordForm');
  if (setupPasswordForm) setupPasswordForm.addEventListener('submit', handleSetupPassword);

  // Check if password is configured
  let authStatus = null;
  try {
    const res = await fetch('/api/auth-status');
    if (res.ok) authStatus = await res.json();
  } catch {}

  const passwordConfigured = authStatus && authStatus.passwordEnabled;

  if (passwordConfigured) {
    // Try session
    const ok = await checkSession();
    if (ok) {
      hideLogin();
      await loadRules();
    } else {
      setAuthNotice('');
      showLogin();
    }
  } else {
    // Password not configured - show setup
    hideLogin();
    showSetupPassword();
  }

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

  const diagBtn = document.getElementById('btn-diagnostics');
  if (diagBtn) diagBtn.addEventListener('click', () => runDiagnostics(diagBtn));

  const addRuleBtn = document.getElementById('btn-add-rule');
  if (addRuleBtn) addRuleBtn.addEventListener('click', () => { showAddRuleDialog(); });

  document.getElementById('btn-modal-close')?.addEventListener('click', closeRuleModal);
  document.getElementById('btn-cancel')?.addEventListener('click', closeRuleModal);
  document.getElementById('ruleForm')?.addEventListener('submit', saveRule);

  document.getElementById('fromLocalPart')?.addEventListener('input', () => { updateFromPreview(); validateRuleForm(); });
  document.getElementById('btn-generate-email-name')?.addEventListener('click', generateEmailName);
  document.getElementById('fromDomain')?.addEventListener('change', () => { updateFromPreview(); validateRuleForm(); });
  document.getElementById('toEmail')?.addEventListener('input', validateRuleForm);
  document.getElementById('workerSelect')?.addEventListener('change', validateRuleForm);
  document.getElementById('ruleType')?.addEventListener('change', () => { updateRuleTypeUI(); validateRuleForm(); });

  const addressSearch = document.getElementById('addressSearch');
  if (addressSearch) addressSearch.addEventListener('input', renderAddressList);
  const addressSort = document.getElementById('addressSort');
  if (addressSort) {
    const savedSort = localStorage.getItem(ADDRESS_SORT_KEY);
    if (savedSort) addressSort.value = savedSort;
    addressSort.addEventListener('change', () => { localStorage.setItem(ADDRESS_SORT_KEY, addressSort.value); renderAddressList(); });
  }

  document.getElementById('address-list')?.addEventListener('click', (e) => {
    const actionBtn = e.target.closest('button[data-action]');
    if (actionBtn) {
      const item = actionBtn.closest('.address-item');
      if (!item) return;
      const ruleId = item.dataset.id;
      const zoneId = item.dataset.zone || null;
      const action = actionBtn.dataset.action;
      if (action === 'copy') { copyAddress(item.dataset.address); return; }
      if (action === 'toggle') return handleAddressToggle(ruleId, zoneId);
      if (action === 'edit') { const rule = state.ruleMap.get(getRuleMapKey(ruleId, zoneId)); if (rule) populateEditRule(rule); return; }
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

  // Load stored address if available and session is active
  if (sessionOk) {
    const storedAddress = localStorage.getItem('selectedAddress');
    if (storedAddress) {
      state.selectedAddress = storedAddress;
      renderAddressList();
      loadInbox(0);
    }
  }
});