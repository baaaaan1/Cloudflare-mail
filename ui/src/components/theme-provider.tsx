import * as React from "react"

import {
  ACCENT_PRESETS,
  DEFAULT_ACCENT,
  type AccentPreset,
} from "@/lib/constants"
import { STORAGE_KEYS } from "@/lib/query-keys"

type Theme = "dark" | "light" | "system"
type ResolvedTheme = "dark" | "light"

type ThemeProviderProps = {
  children: React.ReactNode
  defaultTheme?: Theme
  storageKey?: string
  disableTransitionOnChange?: boolean
}

type ThemeProviderState = {
  theme: Theme
  resolvedTheme: ResolvedTheme
  setTheme: (theme: Theme) => void
  accentId: string
  accent: AccentPreset
  customAccent: string | null
  setAccent: (accentId: string) => void
  setCustomAccent: (hex: string | null) => void
}

const COLOR_SCHEME_QUERY = "(prefers-color-scheme: dark)"
const THEME_VALUES: Theme[] = ["dark", "light", "system"]

const ThemeProviderContext = React.createContext<ThemeProviderState | undefined>(
  undefined
)

function isTheme(value: string | null): value is Theme {
  return value !== null && THEME_VALUES.includes(value as Theme)
}

function getSystemTheme(): ResolvedTheme {
  if (typeof window === "undefined") return "light"
  return window.matchMedia(COLOR_SCHEME_QUERY).matches ? "dark" : "light"
}

function disableTransitionsTemporarily() {
  const style = document.createElement("style")
  style.appendChild(
    document.createTextNode(
      "*,*::before,*::after{-webkit-transition:none!important;transition:none!important}"
    )
  )
  document.head.appendChild(style)

  return () => {
    window.getComputedStyle(document.body)
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        style.remove()
      })
    })
  }
}

function isEditableTarget(target: EventTarget | null) {
  if (!(target instanceof HTMLElement)) return false
  if (target.isContentEditable) return true
  return Boolean(target.closest("input, textarea, select, [contenteditable='true']"))
}

function normalizeHex(value: string) {
  const hex = value.trim().replace(/^#/, "")
  if (/^[0-9a-f]{6}$/i.test(hex)) return `#${hex.toLowerCase()}`
  if (/^[0-9a-f]{3}$/i.test(hex)) {
    return `#${hex
      .split("")
      .map((character) => character + character)
      .join("")}`.toLowerCase()
  }
  return null
}

function hexToRgb(hex: string) {
  const value = normalizeHex(hex)
  if (!value) return null
  const numeric = Number.parseInt(value.slice(1), 16)
  return {
    r: (numeric >> 16) & 255,
    g: (numeric >> 8) & 255,
    b: numeric & 255,
  }
}

function mixHex(hex: string, target: "white" | "black", amount: number) {
  const rgb = hexToRgb(hex)
  if (!rgb) return hex
  const targetValue = target === "white" ? 255 : 0
  const mix = (channel: number) =>
    Math.round(channel + (targetValue - channel) * amount)
  return `#${[mix(rgb.r), mix(rgb.g), mix(rgb.b)]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("")}`
}

function readableForeground(hex: string) {
  const rgb = hexToRgb(hex)
  if (!rgb) return "#ffffff"
  const luminance =
    (0.2126 * rgb.r + 0.7152 * rgb.g + 0.0722 * rgb.b) / 255
  return luminance > 0.62 ? "#101828" : "#ffffff"
}

function resolveAccent(accentId: string, customAccent: string | null, mode: ResolvedTheme) {
  const preset =
    ACCENT_PRESETS.find((item) => item.id === accentId) ?? DEFAULT_ACCENT
  const normalizedCustom = customAccent ? normalizeHex(customAccent) : null

  if (preset.id === "custom" && normalizedCustom) {
    const primary =
      mode === "dark"
        ? mixHex(normalizedCustom, "white", 0.16)
        : normalizedCustom
    return {
      preset: { ...preset, name: "Custom", swatch: normalizedCustom },
      primary,
      foreground: readableForeground(primary),
    }
  }

  return {
    preset,
    primary: mode === "dark" ? preset.dark : preset.light,
    foreground:
      mode === "dark" ? preset.foregroundDark : preset.foregroundLight,
  }
}

export function ThemeProvider({
  children,
  defaultTheme = "system",
  storageKey = STORAGE_KEYS.theme,
  disableTransitionOnChange = true,
  ...props
}: ThemeProviderProps) {
  const [theme, setThemeState] = React.useState<Theme>(() => {
    if (typeof window === "undefined") return defaultTheme
    const storedTheme = localStorage.getItem(storageKey)
    return isTheme(storedTheme) ? storedTheme : defaultTheme
  })

  const [resolvedTheme, setResolvedTheme] = React.useState<ResolvedTheme>(() =>
    theme === "system" ? getSystemTheme() : theme
  )

  const [accentId, setAccentIdState] = React.useState<string>(() => {
    if (typeof window === "undefined") return DEFAULT_ACCENT.id
    return localStorage.getItem(STORAGE_KEYS.accent) || DEFAULT_ACCENT.id
  })

  const [customAccent, setCustomAccentState] = React.useState<string | null>(
    () => {
      if (typeof window === "undefined") return null
      const stored = localStorage.getItem(`${STORAGE_KEYS.accent}.custom`)
      return stored ? normalizeHex(stored) : null
    }
  )

  const setTheme = React.useCallback(
    (nextTheme: Theme) => {
      localStorage.setItem(storageKey, nextTheme)
      setThemeState(nextTheme)
    },
    [storageKey]
  )

  const setAccent = React.useCallback((nextAccent: string) => {
    localStorage.setItem(STORAGE_KEYS.accent, nextAccent)
    setAccentIdState(nextAccent)
  }, [])

  const setCustomAccent = React.useCallback((hex: string | null) => {
    const normalized = hex ? normalizeHex(hex) : null
    if (!normalized) {
      localStorage.removeItem(`${STORAGE_KEYS.accent}.custom`)
      setCustomAccentState(null)
      return
    }
    localStorage.setItem(`${STORAGE_KEYS.accent}.custom`, normalized)
    localStorage.setItem(STORAGE_KEYS.accent, "custom")
    setCustomAccentState(normalized)
    setAccentIdState("custom")
  }, [])

  React.useEffect(() => {
    const root = document.documentElement
    const nextResolved = theme === "system" ? getSystemTheme() : theme
    const restoreTransitions = disableTransitionOnChange
      ? disableTransitionsTemporarily()
      : null

    root.classList.remove("light", "dark")
    root.classList.add(nextResolved)
    root.style.colorScheme = nextResolved
    setResolvedTheme(nextResolved)

    const { primary, foreground } = resolveAccent(
      accentId,
      customAccent,
      nextResolved
    )
    root.style.setProperty("--primary", primary)
    root.style.setProperty("--primary-foreground", foreground)
    root.style.setProperty("--ring", primary)
    root.style.setProperty("--sidebar-primary", primary)
    root.style.setProperty("--sidebar-primary-foreground", foreground)
    root.style.setProperty("--chart-1", primary)
    root.style.setProperty("--brand", primary)
    root.style.setProperty("--brand-foreground", foreground)

    const themeColor = nextResolved === "dark" ? "#0b0f14" : "#f7f8fa"
    document
      .querySelector('meta[name="theme-color"]')
      ?.setAttribute("content", themeColor)

    if (restoreTransitions) restoreTransitions()
  }, [theme, accentId, customAccent, disableTransitionOnChange])

  React.useEffect(() => {
    if (theme !== "system") return undefined
    const mediaQuery = window.matchMedia(COLOR_SCHEME_QUERY)
    const handleChange = () => setThemeState("system")
    mediaQuery.addEventListener("change", handleChange)
    return () => mediaQuery.removeEventListener("change", handleChange)
  }, [theme])

  React.useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.repeat || event.metaKey || event.ctrlKey || event.altKey) return
      if (isEditableTarget(event.target)) return
      if (event.key.toLowerCase() !== "d") return
      setThemeState((currentTheme) => {
        const nextTheme =
          currentTheme === "dark"
            ? "light"
            : currentTheme === "light"
              ? "dark"
              : getSystemTheme() === "dark"
                ? "light"
                : "dark"
        localStorage.setItem(storageKey, nextTheme)
        return nextTheme
      })
    }

    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [storageKey])

  React.useEffect(() => {
    const handleStorageChange = (event: StorageEvent) => {
      if (event.storageArea !== localStorage) return
      if (event.key !== storageKey) return
      if (isTheme(event.newValue)) {
        setThemeState(event.newValue)
        return
      }
      setThemeState(defaultTheme)
    }
    window.addEventListener("storage", handleStorageChange)
    return () => window.removeEventListener("storage", handleStorageChange)
  }, [defaultTheme, storageKey])

  const accent = React.useMemo(
    () => resolveAccent(accentId, customAccent, resolvedTheme).preset,
    [accentId, customAccent, resolvedTheme]
  )

  const value = React.useMemo(
    () => ({
      theme,
      resolvedTheme,
      setTheme,
      accentId,
      accent,
      customAccent,
      setAccent,
      setCustomAccent,
    }),
    [
      theme,
      resolvedTheme,
      setTheme,
      accentId,
      accent,
      customAccent,
      setAccent,
      setCustomAccent,
    ]
  )

  return (
    <ThemeProviderContext.Provider {...props} value={value}>
      {children}
    </ThemeProviderContext.Provider>
  )
}

export function useTheme() {
  const context = React.useContext(ThemeProviderContext)
  if (context === undefined) {
    throw new Error("useTheme must be used within a ThemeProvider")
  }
  return context
}
