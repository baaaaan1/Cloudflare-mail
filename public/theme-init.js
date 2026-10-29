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

    function hexToRgb(hex) {
      var h = parseInt(hex.slice(1), 16);
      return { r: (h >> 16) & 255, g: (h >> 8) & 255, b: h & 255 };
    }
    function rgbToHex(rgb) {
      function c(v) { var s = v.toString(16); return s.length === 1 ? '0' + s : s; }
      return '#' + c(rgb.r) + c(rgb.g) + c(rgb.b);
    }
    function shade(hex, percent) {
      var rgb = hexToRgb(hex);
      var amount = Math.round(255 * percent);
      return rgbToHex({
        r: Math.min(255, Math.max(0, rgb.r + amount)),
        g: Math.min(255, Math.max(0, rgb.g + amount)),
        b: Math.min(255, Math.max(0, rgb.b + amount))
      });
    }
    function applyAccent(accent, accent2, accent3) {
      var root = document.documentElement;
      var rgb = hexToRgb(accent);
      root.style.setProperty('--accent', accent);
      root.style.setProperty('--accent-2', accent2);
      root.style.setProperty('--accent-3', accent3);
      root.style.setProperty('--accent-rgb', rgb.r + ',' + rgb.g + ',' + rgb.b);
    }

    var presets = {
      ocean: { accent: '#277da1', accent2: '#43aa8b', accent3: '#4d908e' },
      sunset: { accent: '#f3722c', accent2: '#f8961e', accent3: '#f9844a' },
      meadow: { accent: '#90be6d', accent2: '#43aa8b', accent3: '#4d908e' },
      coral: { accent: '#f94144', accent2: '#f3722c', accent3: '#f9844a' }
    };
    var custom = localStorage.getItem('accentCustom');
    if (custom && /^#[0-9a-fA-F]{6}$/.test(custom)) {
      applyAccent(custom, shade(custom, 0.2), shade(custom, -0.2));
    } else {
      var presetName = localStorage.getItem('accentPreset');
      if (presets[presetName]) {
        applyAccent(presets[presetName].accent, presets[presetName].accent2, presets[presetName].accent3);
      } else {
        var legacy = localStorage.getItem('accent');
        if (legacy && /^#[0-9a-fA-F]{6}$/.test(legacy)) {
          applyAccent(legacy, shade(legacy, 0.2), shade(legacy, -0.2));
        } else {
          applyAccent(presets.ocean.accent, presets.ocean.accent2, presets.ocean.accent3);
        }
      }
    }
  } catch (e) {}
})();
