export type AccentPreset = {
  id: string
  name: string
  swatch: string
  light: string
  dark: string
  foregroundLight: string
  foregroundDark: string
}

export const ACCENT_PRESETS: AccentPreset[] = [
  {
    id: "aurora",
    name: "Aurora",
    swatch: "#0d9488",
    light: "#0f766e",
    dark: "#2dd4bf",
    foregroundLight: "#ffffff",
    foregroundDark: "#042f2e",
  },
  {
    id: "violet",
    name: "Violet",
    swatch: "#7c3aed",
    light: "#6d28d9",
    dark: "#a78bfa",
    foregroundLight: "#ffffff",
    foregroundDark: "#1e1b4b",
  },
  {
    id: "ocean",
    name: "Ocean",
    swatch: "#2563eb",
    light: "#1d4ed8",
    dark: "#60a5fa",
    foregroundLight: "#ffffff",
    foregroundDark: "#172554",
  },
  {
    id: "emerald",
    name: "Emerald",
    swatch: "#059669",
    light: "#047857",
    dark: "#34d399",
    foregroundLight: "#ffffff",
    foregroundDark: "#022c22",
  },
  {
    id: "sunset",
    name: "Sunset",
    swatch: "#ea580c",
    light: "#c2410c",
    dark: "#fb923c",
    foregroundLight: "#ffffff",
    foregroundDark: "#431407",
  },
  {
    id: "rose",
    name: "Rose",
    swatch: "#e11d48",
    light: "#be123c",
    dark: "#fb7185",
    foregroundLight: "#ffffff",
    foregroundDark: "#4c0519",
  },
]

export const DEFAULT_ACCENT = ACCENT_PRESETS[0]

export type NavItem = {
  to: string
  label: string
  shortLabel: string
  description: string
  icon: "overview" | "inbox" | "addresses" | "rules" | "destinations" | "api" | "settings"
}

export const NAV_ITEMS: NavItem[] = [
  {
    to: "/",
    label: "Overview",
    shortLabel: "Home",
    description: "Workspace at a glance",
    icon: "overview",
  },
  {
    to: "/inbox",
    label: "Inbox",
    shortLabel: "Inbox",
    description: "Read incoming mail",
    icon: "inbox",
  },
  {
    to: "/addresses",
    label: "Addresses",
    shortLabel: "Addresses",
    description: "Your disposable mailboxes",
    icon: "addresses",
  },
  {
    to: "/rules",
    label: "Routing rules",
    shortLabel: "Rules",
    description: "Control email routing",
    icon: "rules",
  },
  {
    to: "/destinations",
    label: "Destinations",
    shortLabel: "Destinations",
    description: "Verified forwarding targets",
    icon: "destinations",
  },
  {
    to: "/docs",
    label: "API docs",
    shortLabel: "API",
    description: "REST reference and API keys",
    icon: "api",
  },
  {
    to: "/settings",
    label: "Settings",
    shortLabel: "Settings",
    description: "Credentials and appearance",
    icon: "settings",
  },
]

export const PAGE_SIZE = 20
