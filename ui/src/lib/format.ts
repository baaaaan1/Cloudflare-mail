export function formatCompactNumber(value: number) {
  return new Intl.NumberFormat(undefined, {
    notation: value > 9999 ? "compact" : "standard",
    maximumFractionDigits: 1,
  }).format(value)
}

export function formatDateTime(value?: string | null) {
  if (!value) return "—"
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return "—"

  const now = new Date()
  const sameYear = date.getFullYear() === now.getFullYear()
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    year: sameYear ? undefined : "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date)
}

export function formatFullDate(value?: string | null) {
  if (!value) return "—"
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return "—"
  return new Intl.DateTimeFormat(undefined, {
    weekday: "short",
    month: "long",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date)
}

export function formatRelativeTime(value?: string | null) {
  if (!value) return "Never"
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return "Never"

  const diff = date.getTime() - Date.now()
  const abs = Math.abs(diff)
  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" })

  if (abs < 45_000) return "Just now"
  if (abs < 3_600_000) return formatter.format(Math.round(diff / 60_000), "minute")
  if (abs < 86_400_000) return formatter.format(Math.round(diff / 3_600_000), "hour")
  if (abs < 604_800_000) return formatter.format(Math.round(diff / 86_400_000), "day")
  if (abs < 2_629_800_000) return formatter.format(Math.round(diff / 604_800_000), "week")
  return formatDateTime(value)
}

export function formatDayGroup(value: string) {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return "Unknown"
  const today = new Date()
  const yesterday = new Date()
  yesterday.setDate(today.getDate() - 1)

  if (date.toDateString() === today.toDateString()) return "Today"
  if (date.toDateString() === yesterday.toDateString()) return "Yesterday"

  return new Intl.DateTimeFormat(undefined, {
    month: "long",
    day: "numeric",
    year: date.getFullYear() === today.getFullYear() ? undefined : "numeric",
  }).format(date)
}

export type SenderInfo = {
  label: string
  email: string
  domain: string
}

function cleanLocalPart(localPart: string) {
  if (!localPart) return ""
  const withoutTag = localPart.replace(/\+.*$/, "")
  const stripped = withoutTag.replace(
    /^(bounce|bounces|noreply|no-reply|donotreply|do-not-reply|mailer-daemon|postmaster|notifications?)[._+-]*/i,
    ""
  )
  return (stripped || withoutTag).trim()
}

function titleCase(value: string) {
  const normalized = value.replace(/[._-]+/g, " ").replace(/\s+/g, " ").trim()
  if (!normalized) return ""
  return normalized.replace(/\b\w/g, (character) => character.toUpperCase())
}

export function parseSender(rawSender?: string | null): SenderInfo {
  const sender = String(rawSender || "").trim()
  let email = ""
  let name = ""

  const bracketMatch = sender.match(/^(.*)<([^>]+@[^>]+)>$/)
  if (bracketMatch) {
    name = bracketMatch[1].replace(/"/g, "").trim()
    email = bracketMatch[2].trim()
  } else if (sender.includes("@")) {
    email = sender
  } else {
    name = sender
  }

  const [rawLocal = "", domain = ""] = email.split("@")
  const localPart = cleanLocalPart(rawLocal)
  const fallback = localPart || rawLocal
  const label = titleCase(name || fallback || email || sender) || "Unknown sender"

  return { label, email, domain }
}

export function getInitials(value: string) {
  const cleaned = value
    .replace(/<[^>]+>/g, " ")
    .replace(/[^\p{L}\p{N}\s.@_-]/gu, " ")
    .trim()

  if (!cleaned) return "?"
  if (cleaned.includes("@")) {
    const local = cleaned.split("@")[0].replace(/[._-]+/g, " ").trim()
    const parts = local.split(/\s+/).filter(Boolean)
    return parts
      .slice(0, 2)
      .map((part) => part[0]?.toUpperCase())
      .join("")
  }

  const parts = cleaned.split(/\s+/).filter(Boolean)
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase()
  return `${parts[0][0] ?? ""}${parts[1][0] ?? ""}`.toUpperCase()
}

const AVATAR_TONES = [
  "bg-teal-500/15 text-teal-700 dark:text-teal-300",
  "bg-sky-500/15 text-sky-700 dark:text-sky-300",
  "bg-violet-500/15 text-violet-700 dark:text-violet-300",
  "bg-amber-500/15 text-amber-700 dark:text-amber-300",
  "bg-rose-500/15 text-rose-700 dark:text-rose-300",
  "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
  "bg-indigo-500/15 text-indigo-700 dark:text-indigo-300",
  "bg-orange-500/15 text-orange-700 dark:text-orange-300",
] as const

export function avatarTone(value: string) {
  let hash = 0
  for (let index = 0; index < value.length; index += 1) {
    hash = (hash * 31 + value.charCodeAt(index)) | 0
  }
  return AVATAR_TONES[Math.abs(hash) % AVATAR_TONES.length]
}

export function localPartOf(address: string) {
  return address.split("@")[0] || address
}

export function domainOf(address: string) {
  return address.split("@")[1] || ""
}

export function normalizeAddress(value: string) {
  return value.trim().toLowerCase()
}

export function pluralize(count: number, singular: string, plural = `${singular}s`) {
  return `${formatCompactNumber(count)} ${count === 1 ? singular : plural}`
}

export function greeting(date = new Date()) {
  const hour = date.getHours()
  if (hour < 5) return "Working late"
  if (hour < 12) return "Good morning"
  if (hour < 18) return "Good afternoon"
  return "Good evening"
}

export async function copyText(value: string) {
  if (!value) throw new Error("Nothing to copy")
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value)
    return
  }

  const textarea = document.createElement("textarea")
  textarea.value = value
  textarea.style.position = "fixed"
  textarea.style.opacity = "0"
  document.body.appendChild(textarea)
  textarea.select()
  document.execCommand("copy")
  textarea.remove()
}

export function sanitizeFilename(value: string) {
  return value.replace(/[^\w.-]+/g, "_").slice(0, 80) || "message"
}
