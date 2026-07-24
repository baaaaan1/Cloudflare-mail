(function () {
  try {
    var stored = localStorage.getItem('theme');
    var body = document.body;
    if (!body) return;
    if (stored === 'dark') {
      body.classList.add('dark-mode');
    } else if (stored === 'light') {
      body.classList.remove('dark-mode');
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      body.classList.add('dark-mode');
    }
    var accent = localStorage.getItem('accent');
    if (accent && /^#[0-9a-fA-F]{6}$/.test(accent)) {
      var h = parseInt(accent.slice(1), 16);
      var r = (h >> 16) & 255;
      var g = (h >> 8) & 255;
      var b = h & 255;
      document.documentElement.style.setProperty('--accent', accent);
      document.documentElement.style.setProperty('--accent-rgb', r + ',' + g + ',' + b);
    }
  } catch (e) {}
})();
