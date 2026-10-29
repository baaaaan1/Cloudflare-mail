// main.js - Flat Tailwind mail client UI for Cloudflare Email Panel
// Simplified: Password-only auth, private mode
const defaultConfig = {
  panel_title: 'Cloudflare Email Panel',
  welcome_message: 'Create an address and read its inbox'
};

const state = {
  createdAddresses: [],
  latestAddress: null,
  inbox: [],
  inboxPage: 0,
  inboxLimit: 20,
  domains: [],
  domainsLoaded: false,
  domainsLoading: false,
  domainsError: null,
  workers: [],
  workersLoaded: false,
  workersLoading: false,
  workersError: null,
  currentEmailId: null,
  currentEmailData: null
};

let sessionOk = false;
let csrfToken = null;
let passwordConfigured = false;

const accentPresets = {
  ocean: { accent: '#277da1', accent2: '#43aa8b', accent3: '#4d908e' },
  sunset: { accent: '#f3722c', accent2: '#f8961e', accent3: '#f9844a' },
  meadow: { accent: '#90be6d', accent2: '#43aa8b', accent3: '#4d908e' },
  coral: { accent: '#f94144', accent2: '#f3722c', accent3: '#f9844a' }
};

const CREATED_ADDRESSES_KEY = 'createdAddresses';
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

function createRandomLocalPart(style = 'us') {
  const parts = emailNameParts[style] || emailNameParts.us;
  const suffix = String(Math.floor(Math.random() * 900) + 100);
  return `${randomItem(parts.first)}.${randomItem(parts.last)}${suffix}`;
}

function getNameStyle() {
  const select = document.getElementById('nameStyle');
  const value = select?.value;
  return value === 'id' ? 'id' : 'us';
}

function generateCreateName() {
  const input = document.getElementById('createName');
  if (!input) return;
  input.value = createRandomLocalPart(getNameStyle());
  setCreateError('');
  input.focus();
}

function setCreateError(message = '') {
  const error = document.getElementById('createError');
  if (error) error.textContent = message;
}

function setCreateLoading(loading) {
  const submit = document.getElementById('btn-create-address');
  const randomBtn = document.getElementById('btn-create-random');
  const nameBtn = document.getElementById('btn-random-name');
  if (submit) {
    submit.disabled = loading;
    submit.textContent = loading ? 'Creating...' : 'Create Address';
  }
  if (randomBtn) randomBtn.disabled = loading;
  if (nameBtn) nameBtn.disabled = loading;
}

async function api(path, opts = {}) {
  const headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
  const method = String(opts.method || 'GET').toUpperCase();
  if (csrfToken && !['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    headers['X-CSRF-Token'] = csrfToken;
  }
  const res = await fetch(path, Object.assign({ headers, credentials: 'include' }, opts));
  if (res.status === 401) {
    sessionOk = false;
    csrfToken = null;
    window.location.href = '/login';
    throw new Error('Unauthorized');
  }
  if (!res.ok) throw new Error((await res.text()) || res.statusText);
  return res.json();
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
  const rgb = hexToRgb(accent);
  root.style.setProperty('--accent-rgb', rgb ? `${rgb.r}, ${rgb.g}, ${rgb.b}` : '39, 125, 161');
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
  const stored = localStorage.getItem('accentPreset');
  const legacyMap = { purple: 'coral', emerald: 'meadow', amber: 'sunset' };
  const preset = accentPresets[stored] ? stored : (legacyMap[stored] || 'ocean');
  if (custom && applyCustomAccent(custom)) return;
  applyAccentPreset(preset);
}

function syncAccentInputs(hex) {
  const picker = document.getElementById('accentPicker');
  const display = document.getElementById('accentHexDisplay');
  if (picker) picker.value = hex;
  if (display) display.value = hex;
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

function isSidebarOpen() {
  return document.body.classList.contains('sidebar-open');
}

function updateSidebarToggle(state) {
  const toggle = document.getElementById('sidebarToggle');
  const sidebar = document.getElementById('sidebar');
  const isOpen = state === 'open';
  if (toggle) toggle.setAttribute('aria-expanded', String(isOpen));
  if (sidebar) {
    sidebar.setAttribute('aria-hidden', String(!isOpen));
    sidebar.inert = !isOpen;
  }
}

function showView() {
  const el = document.querySelector('.mail-layout');
  if (el) el.style.display = '';
}

function setSidebarState(state, options = {}) {
  const sidebar = document.getElementById('sidebar');
  const overlay = document.getElementById('sidebarOverlay');
  const wasOpen = isSidebarOpen();
  const isOpen = state === 'open';
  document.body.classList.toggle('sidebar-open', isOpen);
  if (sidebar) {
    sidebar.classList.toggle('is-open', isOpen);
    sidebar.classList.toggle('is-collapsed', !isOpen);
  }
  if (overlay) overlay.classList.toggle('is-open', isOpen);
  try {
    localStorage.setItem(SIDEBAR_STATE_KEY, state);
  } catch {}
  updateSidebarToggle(state);
  if (!isOpen && wasOpen && options.focusToggle) {
    document.getElementById('sidebarToggle')?.focus();
  }
}

function toggleSidebar() {
  setSidebarState(isSidebarOpen() ? 'collapsed' : 'open');
}

async function checkSession() {
  try {
    const data = await api('/api/session');
    sessionOk = !!data.ok;
    if (data.csrfToken) csrfToken = data.csrfToken;
    return sessionOk;
  } catch {
    sessionOk = false;
    csrfToken = null;
    return false;
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
  syncTokenToggleVisibility(document.getElementById('cfgApiToken'), document.getElementById('cfgApiTokenToggle'));
  syncTokenToggleVisibility(document.getElementById('cfgAdminApiToken'), document.getElementById('cfgAdminApiTokenToggle'));
}

function syncTokenToggleVisibility(input, button) {
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
    document.getElementById('cfgD1DatabaseId').value = config.d1_database_id || '';
    const tokenInput = document.getElementById('cfgApiToken');
    tokenInput.value = '';
    tokenInput.placeholder = config.has_token ? '******** (Set to update)' : 'Enter API Token';
    updateTokenToggleVisibility();
    const adminTokenInput = document.getElementById('cfgAdminApiToken');
    if (adminTokenInput) {
      adminTokenInput.value = '';
      adminTokenInput.placeholder = config.has_admin_api_token ? '******** (Set to update)' : 'Enter Admin API Token';
    }
  } catch (e) {
    showNotification('Could not load config: ' + e.message, 'error');
  }
}

async function saveSettings(e) {
  e.preventDefault();
  const body = {
    account_id: document.getElementById('cfgAccountId').value.trim(),
    d1_database_id: document.getElementById('cfgD1DatabaseId').value.trim(),
    api_token: document.getElementById('cfgApiToken').value.trim(),
    admin_api_token: document.getElementById('cfgAdminApiToken').value.trim()
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
  updateCreateDomainSelect();
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
  updateCreateDomainSelect();
  return state.domains;
}

async function loadWorkers(force = false) {
  if (state.workersLoaded && !force) return state.workers;
  if (state.workersLoading) return state.workers;
  state.workersLoading = true;
  state.workersError = null;
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
  return state.workers;
}

function updateCreateDomainSelect() {
  const select = document.getElementById('createDomain');
  if (!select) return;
  const currentValue = select.value;
  select.innerHTML = '';
  if (state.domainsLoading) {
    select.disabled = true;
    select.appendChild(new Option('Loading domains...', ''));
    return;
  }
  if (state.domainsError) {
    select.disabled = true;
    select.appendChild(new Option('Failed to load domains', ''));
    return;
  }
  if (!state.domains.length) {
    select.disabled = true;
    select.appendChild(new Option('No domains available', ''));
    return;
  }
  state.domains.forEach((domain) => {
    if (!domain || !domain.id || !domain.name) return;
    select.appendChild(new Option(domain.name, domain.id));
  });
  select.disabled = false;
  if (currentValue && Array.from(select.options).some((opt) => opt.value === currentValue)) {
    select.value = currentValue;
  }
}

function getSelectedCreateDomain() {
  const select = document.getElementById('createDomain');
  if (!select || select.disabled || !select.value) return null;
  const option = select.options[select.selectedIndex];
  const name = (option?.textContent || '').trim();
  if (!name) return null;
  return { id: select.value.trim(), name };
}

function validateLocalPart(value) {
  if (!value) return 'Nama email wajib diisi.';
  if (value.includes('@')) return 'Jangan gunakan @ pada nama email.';
  if (/\s/.test(value)) return 'Tidak boleh ada spasi.';
  if (!/^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(value)) return 'Format nama email tidak valid.';
  return '';
}

function loadCreatedAddresses() {
  try {
    const raw = localStorage.getItem(CREATED_ADDRESSES_KEY);
    const parsed = raw ? JSON.parse(raw) : [];
    if (!Array.isArray(parsed)) return [];
    return parsed
      .map((value) => String(value || '').trim().toLowerCase())
      .filter(Boolean)
      .filter((value, index, list) => list.indexOf(value) === index);
  } catch {
    return [];
  }
}

function saveCreatedAddresses() {
  try {
    localStorage.setItem(CREATED_ADDRESSES_KEY, JSON.stringify(state.createdAddresses));
  } catch {}
}

function addCreatedAddress(address) {
  const normalized = String(address || '').trim().toLowerCase();
  if (!normalized) return;
  state.latestAddress = normalized;
  if (!state.createdAddresses.includes(normalized)) {
    state.createdAddresses.push(normalized);
    saveCreatedAddresses();
  }
  renderViewingPanel();
}

async function loadLatestGeneratedAddress() {
  try {
    const latest = await api('/api/addresses/latest');
    const address = String(latest?.address || '').trim().toLowerCase();
    state.latestAddress = address || null;
    if (address && !state.createdAddresses.includes(address)) {
      state.createdAddresses.push(address);
      saveCreatedAddresses();
    }
    renderViewingPanel();
  } catch {}
}

function renderViewingPanel() {
  const panel = document.getElementById('viewingPanel');
  const list = document.getElementById('viewingList');
  if (!panel || !list) return;
  const address = state.latestAddress || '';
  if (!address) {
    panel.hidden = true;
    list.innerHTML = '';
    return;
  }
  panel.hidden = false;
  list.innerHTML = '';

  const item = document.createElement('div');
  item.className = 'viewing-item';

  const label = document.createElement('span');
  label.className = 'viewing-address';
  label.title = address;
  const prefix = document.createElement('span');
  prefix.className = 'viewing-address-prefix';
  prefix.textContent = 'Viewing';
  label.appendChild(prefix);
  label.appendChild(document.createTextNode(address));

  const copyBtn = document.createElement('button');
  copyBtn.type = 'button';
  copyBtn.className = 'ui-button ui-button-outline viewing-copy';
  copyBtn.title = 'Copy address';
  copyBtn.setAttribute('aria-label', `Copy ${address}`);
  copyBtn.dataset.copyAddress = address;
  const icon = document.createElement('span');
  icon.className = 'material-icons';
  icon.textContent = 'content_copy';
  copyBtn.appendChild(icon);

  item.appendChild(label);
  item.appendChild(copyBtn);
  list.appendChild(item);
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

async function getInboxWorkerName() {
  if (!state.workersLoaded && !state.workersLoading) await loadWorkers();
  const worker = state.workers.find((item) => /inbox/i.test(item.name || '')) || state.workers[0];
  return worker?.name || 'inbox-worker';
}

async function handleCreateAddress(randomize = false) {
  const nameInput = document.getElementById('createName');
  const domainSelect = document.getElementById('createDomain');
  if (!nameInput) return;
  setCreateError('');
  let localPart = nameInput.value.trim();
  if (randomize) {
    localPart = createRandomLocalPart(getNameStyle());
    nameInput.value = localPart;
    const availableDomains = state.domains.filter((item) => item && item.id && item.name);
    if (availableDomains.length && domainSelect) {
      const domain = randomItem(availableDomains);
      domainSelect.value = domain.id;
    }
  }
  const localError = validateLocalPart(localPart);
  if (localError) {
    setCreateError(localError);
    nameInput.focus();
    return;
  }
  if (state.domainsLoading) {
    setCreateError('Daftar domain sedang dimuat.');
    return;
  }
  if (state.domainsError) {
    setCreateError('Gagal memuat domain.');
    return;
  }
  const domain = getSelectedCreateDomain();
  if (!domain) {
    setCreateError('Pilih domain yang valid.');
    return;
  }
  setCreateLoading(true);
  try {
    const workerName = await getInboxWorkerName();
    const email = `${localPart}@${domain.name}`;
    await api('/api/rules', {
      method: 'POST',
      body: JSON.stringify({
        customEmail: email,
        destinationIdManual: workerName,
        type: 'worker',
        zoneId: domain.id
      })
    });
    try {
      await api('/api/addresses', {
        method: 'POST',
        body: JSON.stringify({ address: email })
      });
    } catch (e) {
      console.warn('Failed to persist generated address', e);
    }
    addCreatedAddress(email);
    showNotification('Address created', 'success');
    nameInput.value = '';
    await loadInbox(0);
  } catch (e) {
    setCreateError(e.message);
    showNotification('Create address failed: ' + e.message, 'error');
  } finally {
    setCreateLoading(false);
  }
}

async function loadInbox(page = 0) {
  const list = document.getElementById('inbox-list');
  const empty = document.getElementById('inbox-empty');
  const prev = document.getElementById('btn-inbox-prev');
  const next = document.getElementById('btn-inbox-next');
  const address = state.latestAddress || '';
  if (!address) {
    list.innerHTML = '';
    empty.style.display = 'block';
    empty.textContent = 'Create an address to view messages.';
    if (prev) prev.disabled = true;
    if (next) next.disabled = true;
    return;
  }
  empty.style.display = 'none';
  list.innerHTML = '<div class="loading">Loading messages...</div>';
  try {
    const recipients = encodeURIComponent(address);
    const emails = await api(`/api/inbox?limit=${state.inboxLimit}&offset=${page * state.inboxLimit}&recipients=${recipients}`);
    state.inbox = Array.isArray(emails) ? emails : [];
    state.inboxPage = page;
    renderInbox();
    if (prev) prev.disabled = state.inboxPage === 0;
    if (next) next.disabled = state.inbox.length < state.inboxLimit;
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
    const toLabel = email.recipient || '-';
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

function wrapEmailHtml(html) {
  const content = String(html || '').trim();
  if (!content) return '';
  const baseStyle = 'img{max-width:100%!important;height:auto!important}table{max-width:100%}body{margin:0;padding:12px;background:#ffffff;color:#1a1a2e;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;line-height:1.5;word-break:break-word}a{color:#277da1}';
  // Full HTML document - inject styles without nesting another document
  if (/^<!DOCTYPE/i.test(content) || /<html[\s>]/i.test(content)) {
    if (/<\/head>/i.test(content)) {
      return content.replace(/<\/head>/i, `<style>${baseStyle}</style></head>`);
    }
    if (/<body[\s>]/i.test(content)) {
      return content.replace(/<body([^>]*)>/i, `<body$1><style>${baseStyle}</style>`);
    }
    return content;
  }
  // HTML fragment - wrap in minimal document with light email-safe defaults
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>${baseStyle}</style></head><body>${content}</body></html>`;
}

function renderEmailBody(type) {
  try {
    const container = document.getElementById('emailBodyContainer');
    const btnHtml = document.getElementById('btn-view-html');
    const btnText = document.getElementById('btn-view-text');
    const data = state.currentEmailData;
    
    if (type === 'html') {
      btnHtml.classList.add('active');
      btnText.classList.remove('active');
      const htmlContent = data?.html_body;
      if (htmlContent && String(htmlContent).trim()) {
        const iframe = document.createElement('iframe');
        iframe.className = 'email-body-iframe';
        // allow-same-origin allows loading images/resources from same origin
        // allow-popups allows links to open in new tabs
        // allow-popups-to-escape-sandbox allows popups to escape sandbox
        iframe.setAttribute('sandbox', 'allow-same-origin allow-popups allow-popups-to-escape-sandbox');
        iframe.setAttribute('referrerpolicy', 'no-referrer');
        iframe.setAttribute('title', 'Email content');
        iframe.srcdoc = wrapEmailHtml(htmlContent);
        container.innerHTML = '';
        container.appendChild(iframe);
      } else {
        // No HTML content - try text_body as fallback
        const textFallback = data?.text_body ? String(data.text_body).trim() : '';
        container.innerHTML = '';
        const div = document.createElement('div');
        div.className = 'email-body-text';
        div.textContent = textFallback || '(No HTML or text content)';
        container.appendChild(div);
      }
    } else {
      btnHtml.classList.remove('active');
      btnText.classList.add('active');
      const textContent = data?.text_body ? String(data.text_body).trim() : '(No text content)';
      container.innerHTML = '';
      const div = document.createElement('div');
      div.className = 'email-body-text';
      div.textContent = textContent || '(No text content)';
      container.appendChild(div);
    }
  } catch (e) {
    // Fallback error display
    const container = document.getElementById('emailBodyContainer');
    if (container) {
      container.innerHTML = '';
      const div = document.createElement('div');
      div.className = 'email-body-text';
      div.style.color = '#ef4444';
      div.textContent = 'Error rendering email: ' + e.message;
      container.appendChild(div);
    }
    console.error('renderEmailBody error:', e);
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
  csrfToken = null;
  state.inbox = [];
  state.inboxPage = 0;
  state.currentEmailId = null;
  state.currentEmailData = null;
  sessionOk = false;
  const inboxList = document.getElementById('inbox-list');
  if (inboxList) inboxList.innerHTML = '';
  const inboxEmpty = document.getElementById('inbox-empty');
  if (inboxEmpty) { inboxEmpty.style.display = 'block'; inboxEmpty.textContent = 'Create an address to view messages.'; }
  closeEmailViewer();
  window.location.href = '/login';
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

  const sidebarToggle = document.getElementById('sidebarToggle');
  if (sidebarToggle) sidebarToggle.addEventListener('click', toggleSidebar);
  const sidebarClose = document.getElementById('sidebarClose');
  if (sidebarClose) sidebarClose.addEventListener('click', () => setSidebarState('collapsed', { focusToggle: true }));
  const sidebarOverlay = document.getElementById('sidebarOverlay');
  if (sidebarOverlay) sidebarOverlay.addEventListener('click', () => setSidebarState('collapsed', { focusToggle: true }));
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && isSidebarOpen()) {
      setSidebarState('collapsed', { focusToggle: true });
    }
  });
  let savedState = null;
  try {
    savedState = localStorage.getItem(SIDEBAR_STATE_KEY);
  } catch {}
  if (savedState === 'open' || savedState === 'collapsed') setSidebarState(savedState);
  else setSidebarState('collapsed');

  state.createdAddresses = loadCreatedAddresses();
  state.latestAddress = state.createdAddresses[state.createdAddresses.length - 1] || null;
  renderViewingPanel();

  // Auth gate — pengguna tanpa session dialihkan ke halaman /login
  let authStatus = null;
  try {
    const res = await fetch('/api/auth-status');
    if (res.ok) authStatus = await res.json();
  } catch {}

  passwordConfigured = !!(authStatus && authStatus.passwordEnabled);

  if (passwordConfigured) {
    const ok = await checkSession();
    if (ok) {
      await loadLatestGeneratedAddress();
      await loadDomains();
      showView();
      loadInbox(0);
    } else {
      window.location.href = '/login';
      return;
    }
  } else {
    // Password belum dikonfigurasi → arahkan ke halaman /login (mode setup)
    window.location.href = '/login';
    return;
  }

  const settingsForm = document.getElementById('settingsForm');
  if (settingsForm) {
    settingsForm.addEventListener('submit', saveSettings);
    settingsForm.addEventListener('click', handleSettingsAction);
  }

  const tokenInput = document.getElementById('cfgApiToken');
  if (tokenInput) tokenInput.addEventListener('input', updateTokenToggleVisibility);
  const adminTokenInput = document.getElementById('cfgAdminApiToken');
  if (adminTokenInput) adminTokenInput.addEventListener('input', updateTokenToggleVisibility);

  const logoutBtn = document.getElementById('btn-logout');
  if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);

  const checkBtn = document.getElementById('btn-check-status');
  if (checkBtn) checkBtn.addEventListener('click', () => checkApiStatus(checkBtn));

  const diagBtn = document.getElementById('btn-diagnostics');
  if (diagBtn) diagBtn.addEventListener('click', () => runDiagnostics(diagBtn));

  document.getElementById('createAddressForm')?.addEventListener('submit', (event) => {
    event.preventDefault();
    handleCreateAddress(false);
  });
  document.getElementById('btn-random-name')?.addEventListener('click', generateCreateName);
  document.getElementById('btn-create-random')?.addEventListener('click', () => handleCreateAddress(true));
  document.getElementById('createName')?.addEventListener('input', () => setCreateError(''));
  document.getElementById('createDomain')?.addEventListener('change', () => setCreateError(''));
  const nameStyleSelect = document.getElementById('nameStyle');
  if (nameStyleSelect) {
    const savedStyle = localStorage.getItem('nameStyle');
    if (savedStyle === 'id' || savedStyle === 'us') nameStyleSelect.value = savedStyle;
    nameStyleSelect.addEventListener('change', () => localStorage.setItem('nameStyle', nameStyleSelect.value));
  }

  document.getElementById('viewingList')?.addEventListener('click', (event) => {
    const copyBtn = event.target.closest('[data-copy-address]');
    if (!copyBtn) return;
    copyToClipboard(copyBtn.dataset.copyAddress, 'Email disalin', 'Gagal menyalin');
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
});
