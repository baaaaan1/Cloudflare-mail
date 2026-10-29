export const queryKeys = {
  auth: ["auth-status"] as const,
  session: ["session"] as const,
  domains: ["domains"] as const,
  workers: ["workers"] as const,
  destinations: ["destinations"] as const,
  rules: (zoneId: string | null) => ["rules", zoneId] as const,
  latestAddress: ["latest-address"] as const,
  inboxSummary: ["inbox-summary"] as const,
  inbox: (scope: string, page: number) => ["inbox", scope, page] as const,
  email: (id: number | string | null) => ["email", id] as const,
  config: ["config"] as const,
  diagnostics: ["diagnostics"] as const,
  apiKeys: ["api-keys"] as const,
  health: ["health"] as const,
}

export const STORAGE_KEYS = {
  savedAddresses: "cfmail.saved-addresses",
  activeMailbox: "cfmail.active-mailbox",
  readMessages: "cfmail.read-messages",
  nameStyle: "cfmail.name-style",
  accent: "cfmail.accent",
  theme: "theme",
} as const
