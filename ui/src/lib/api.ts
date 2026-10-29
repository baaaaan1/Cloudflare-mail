import type {
  ApiKeyListResponse,
  AuthStatus,
  ConfigPayload,
  CreatedApiKey,
  CreateRulePayload,
  Destination,
  Diagnostics,
  Domain,
  EmailDetail,
  EmailSummaryItem,
  Health,
  InboxSummaryRow,
  LatestAddress,
  PanelConfig,
  Rule,
  SessionInfo,
  UpdateRulePayload,
  Worker,
} from "@/lib/types"

export class ApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = "ApiError"
    this.status = status
  }
}

type ApiOptions = Omit<RequestInit, "body"> & {
  body?: unknown
  silent401?: boolean
}

function extractMessage(payload: unknown, fallback: string) {
  if (typeof payload === "string" && payload.trim()) {
    const text = payload.trim()
    try {
      const parsed = JSON.parse(text) as { error?: string; message?: string }
      return parsed.error || parsed.message || text
    } catch {
      return text
    }
  }

  if (payload && typeof payload === "object") {
    const record = payload as { error?: unknown; message?: unknown }
    if (typeof record.error === "string" && record.error.trim()) return record.error
    if (typeof record.message === "string" && record.message.trim()) return record.message
  }

  return fallback
}

export async function api<T>(path: string, options: ApiOptions = {}): Promise<T> {
  const { body, silent401, headers: inputHeaders, ...rest } = options
  const headers = new Headers(inputHeaders)

  if (body !== undefined && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json")
  }

  const response = await fetch(path, {
    credentials: "include",
    ...rest,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  if (response.status === 401 && !silent401) {
    window.dispatchEvent(new Event("cfmail:unauthorized"))
  }

  const text = await response.text()
  let payload: unknown = null
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = text
    }
  }

  if (!response.ok) {
    throw new ApiError(
      extractMessage(payload, text || response.statusText || "Request failed"),
      response.status
    )
  }

  return payload as T
}

export const apiClient = {
  authStatus: () => api<AuthStatus>("/api/auth-status", { silent401: true }),
  session: () => api<SessionInfo>("/api/session", { silent401: true }),
  login: async (password: string, turnstileToken?: string) => {
    const result = await api<{ ok: boolean }>("/api/auth/login", {
      method: "POST",
      body: turnstileToken ? { password, turnstileToken } : { password },
      silent401: true,
    })
    return result
  },
  logout: () => api<{ ok: boolean }>("/api/logout", { method: "POST", silent401: true }),

  domains: () => api<Domain[]>("/api/domains"),
  workers: () => api<Worker[]>("/api/workers"),
  destinations: () => api<Destination[]>("/api/destinations"),
  createDestination: (email: string) =>
    api<Destination>("/api/destinations", { method: "POST", body: { email } }),
  deleteDestination: (id: string) =>
    api<{ ok: boolean }>(`/api/destinations/${encodeURIComponent(id)}`, { method: "DELETE" }),

  rules: (zoneId: string) =>
    api<Rule[]>(`/api/rules?zoneId=${encodeURIComponent(zoneId)}`),
  createRule: (payload: CreateRulePayload) =>
    api<Rule>("/api/rules", { method: "POST", body: payload }),
  updateRule: (id: string, payload: UpdateRulePayload) =>
    api<Rule>(`/api/rules/${encodeURIComponent(id)}`, { method: "PUT", body: payload }),
  deleteRule: (id: string, zoneId: string) =>
    api<{ ok: boolean }>(`/api/rules/${encodeURIComponent(id)}`, {
      method: "DELETE",
      body: { zoneId },
    }),

  latestAddress: () => api<LatestAddress>("/api/addresses/latest"),
  saveAddress: (address: string) =>
    api<{ ok: boolean }>("/api/addresses", { method: "POST", body: { address } }),

  inboxSummary: () => api<InboxSummaryRow[]>("/api/inbox/summary"),
  inbox: (params: { limit: number; offset: number; recipients?: string }) => {
    const query = new URLSearchParams({
      limit: String(params.limit),
      offset: String(params.offset),
    })
    if (params.recipients) query.set("recipients", params.recipients)
    return api<EmailSummaryItem[]>(`/api/inbox?${query.toString()}`)
  },
  email: (id: number | string) => api<EmailDetail>(`/api/inbox/${encodeURIComponent(id)}`),
  deleteEmail: (id: number | string) =>
    api<{ ok: boolean }>(`/api/inbox/${encodeURIComponent(id)}`, { method: "DELETE" }),
  initInbox: () => api<{ ok: boolean }>("/api/inbox/init", { method: "POST" }),

  config: () => api<PanelConfig>("/api/config"),
  saveConfig: (payload: ConfigPayload) =>
    api<{ ok: boolean }>("/api/config", { method: "POST", body: payload }),
  diagnostics: () => api<Diagnostics>("/api/diagnostics"),
  health: () => api<Health>("/health"),
  catchAll: (payload: { zoneId: string; action: string; destinationId?: string }) =>
    api<{ ok: boolean }>("/api/catch-all", { method: "POST", body: payload }),

  apiKeys: () => api<ApiKeyListResponse>("/api/keys"),
  createApiKey: (payload: { name: string; scopes: string[] }) =>
    api<CreatedApiKey>("/api/keys", { method: "POST", body: payload }),
  deleteApiKey: (id: string) =>
    api<{ ok: boolean }>(`/api/keys/${encodeURIComponent(id)}`, { method: "DELETE" }),
}
