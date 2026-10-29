/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./public/index.html', './public/main.js', './public/theme-init.js', './public/login.html', './public/login.js'],
  darkMode: ['class', '[class~="dark-mode"]'],
  theme: {
    extend: {
      colors: {
        accent: 'var(--accent, #277da1)',
        accent2: 'var(--accent-2, #43aa8b)',
        accent3: 'var(--accent-3, #4d908e)',
      },
      fontFamily: {
        sans: ['"Space Grotesk"', 'system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
