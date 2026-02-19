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
  } catch (e) {}
})();
