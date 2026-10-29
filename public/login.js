(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);

  function setNotice(el, message, type) {
    if (!el) return;
    el.textContent = message || '';
    el.classList.toggle('is-hidden', !message);
    el.classList.remove('is-error', 'is-success', 'is-warning');
    if (type) el.classList.add('is-' + type);
  }

  function clearNotices() {
    setNotice($('authNotice'), null);
    setNotice($('setupNotice'), null);
  }

  // ── Check if already logged in ──────────────────────────────────────────
  async function checkStatus() {
    try {
      const res = await fetch('/api/auth-status', { credentials: 'include' });
      if (res.ok) {
        const status = await res.json();
        if (status.loggedIn) {
          window.location.href = '/';
          return;
        }
        if (!status.passwordEnabled) {
          setNotice(
            $('setupNotice'),
            'APP_PASSWORD belum di-set. Tambahkan APP_PASSWORD=... di file .env lalu restart server.',
            'warning'
          );
        }
      }
    } catch (e) {}
    const pwd = $('passwordInput');
    if (pwd) pwd.focus();
  }

  // ── Show/hide password toggle ─────────────────────────────────────────────
  const toggleBtn = $('togglePwd');
  const pwdIcon = $('pwdIcon');
  const pwdInput = $('passwordInput');
  if (toggleBtn && pwdInput && pwdIcon) {
    toggleBtn.addEventListener('click', () => {
      const isText = pwdInput.type === 'text';
      pwdInput.type = isText ? 'password' : 'text';
      pwdIcon.textContent = isText ? 'visibility' : 'visibility_off';
    });
  }

  // ── Submit login ──────────────────────────────────────────────────────────
  async function submitLogin(e) {
    e.preventDefault();
    clearNotices();

    const password = (pwdInput && pwdInput.value) || '';
    if (!password) {
      setNotice($('authNotice'), 'Password wajib diisi.', 'error');
      return;
    }

    const btn = $('loginBtn');
    const originalText = btn.textContent;
    btn.textContent = 'Loading...';
    btn.disabled = true;

    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ password }),
      });

      const data = await res.json().catch(() => ({}));

      if (res.ok && data.ok) {
        setNotice($('authNotice'), 'Login berhasil! Mengalihkan...', 'success');
        setTimeout(() => { window.location.href = '/'; }, 500);
        return;
      }

      setNotice($('authNotice'), data.error || 'Password salah.', 'error');
    } catch (err) {
      setNotice($('authNotice'), 'Gagal terhubung ke server.', 'error');
    } finally {
      btn.textContent = originalText;
      btn.disabled = false;
    }
  }

  const form = $('loginForm');
  if (form) form.addEventListener('submit', submitLogin);

  checkStatus();
})();
