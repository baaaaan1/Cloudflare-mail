export type Domain = {
  id: string
  name: string
}

export type Worker = {
  id: string
  name: string
}

export type Destination = {
  id: string
  email: string
  verified?: boolean | string | null
  created?: string
  modified?: string
}

export type RuleAction = {
  type: "forward" | "worker" | "drop" | string
  value?: string[]
}

export type RuleMatcher = {
  type: string
  field?: string
  value?: string
}

export type Rule = {
  id: string
  name?: string
  enabled?: boolean
  priority?: number
  matchers?: RuleMatcher[]
  actions?: RuleAction[]
}

export type EmailSummaryItem = {
  id: number
  sender: string | null
  recipient: string | null
  subject: string | null
  created_at: string
}

export type EmailDetail = EmailSummaryItem & {
  text_body?: string | null
  html_body?: string | null
}

export type InboxSummaryRow = {
  recipient: string
  latest_at: string | null
  first_at: string | null
  total: number | string
}

export type LatestAddress = {
  address: string
  created_at?: string
} | null

export type PanelConfig = {
  account_id: string
  d1_database_id: string
  has_token: boolean
  has_admin_api_token: boolean
}

export type ConfigPayload = {
  account_id: string
  d1_database_id: string
  api_token?: string
  admin_api_token?: string
}

export type DiagnosticCheck = {
  name: string
  ok: boolean
  detail: string
  hint?: string
}

export type Diagnostics = {
  ok: boolean
  checks: DiagnosticCheck[]
}

export type Health = {
  ok: boolean
  destinations: number
  routes?: number
  warnings: string[]
}

export type AuthStatus = {
  loggedIn: boolean
  authRequired: boolean
  passwordEnabled: boolean
  turnstileEnabled?: boolean
  turnstileSiteKey?: string
  role?: string
}

export type ApiKey = {
  id: string
  name: string
  prefix: string
  scopes: string[]
  createdAt: string
  lastUsedAt: string | null
}

export type ApiKeyListResponse = {
  apiKeys: ApiKey[]
  total: number
  availableScopes?: string[]
}

export type CreatedApiKey = {
  key: string
  apiKey: ApiKey
}

export type SessionInfo = {
  ok: boolean
  role?: string
  email?: string
}

export type CreateRulePayload = {
  customEmail: string
  destinationId?: string
  destinationIdManual?: string
  type: "worker" | "forward" | "drop"
  zoneId: string
}

export type UpdateRulePayload = {
  customEmail?: string
  destinationId?: string
  enabled?: boolean
  type?: "worker" | "forward" | "drop"
  zoneId: string
}

export type CreateAddressPayload = {
  localPart: string
  domain: Domain
  style: NameStyle
}

export type NameStyle = "us" | "id"

export type Mailbox = {
  address: string
  localPart: string
  domain: string
  total: number
  latestAt: string | null
  saved: boolean
}

