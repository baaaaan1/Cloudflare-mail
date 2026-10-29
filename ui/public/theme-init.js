;(() => {
  try {
    const stored = localStorage.getItem("theme")
    const systemDark = window.matchMedia("(prefers-color-scheme: dark)").matches
    const theme =
      stored === "dark" || stored === "light" ? stored : systemDark ? "dark" : "light"
    document.documentElement.classList.add(theme)
    document.documentElement.style.colorScheme = theme
  } catch (error) {
    document.documentElement.classList.add("light")
  }
})()
