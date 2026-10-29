import * as React from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"

import { apiClient } from "@/lib/api"
import { normalizeAddress } from "@/lib/format"
import { queryKeys, STORAGE_KEYS } from "@/lib/query-keys"
import type { Domain, Health, InboxSummaryRow, LatestAddress, Mailbox, PanelConfig, SessionInfo, Worker } from "@/lib/types"

type WorkspaceContextValue = {
  domains: Domain[]
  workers: Worker[]
  summary: InboxSummaryRow[]
  latestAddress: LatestAddress
  config: PanelConfig | undefined
  health: Health | undefined
  healthError: Error | null
  session: SessionInfo | undefined
  addresses: Mailbox[]
  savedAddresses: string[]
  activeAddress: string | null
  totalMessages: number
  mailboxCount: number
  domainsLoading: boolean
  domainsError: Error | null
  summaryLoading: boolean
  summaryError: Error | null
  setActiveAddress: (address: string) => void
  addSavedAddress: (address: string) => void
  removeSavedAddress: (address: string) => void
  refreshWorkspace: () => Promise<void>
  isAddressSaved: (address: string) => boolean
}

const WorkspaceContext = React.createContext<WorkspaceContextValue | undefined>(
  undefined
)

function readSavedAddresses() {
  if (typeof window === "undefined") return []
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.savedAddresses)
    const parsed = raw ? (JSON.parse(raw) as unknown) : []
    if (!Array.isArray(parsed)) return []
    return Array.from(
      new Set(
        parsed
          .map((item) => normalizeAddress(String(item || "")))
          .filter(Boolean)
      )
    )
  } catch {
    return []
  }
}

function readActiveAddress() {
  if (typeof window === "undefined") return ""
  return localStorage.getItem(STORAGE_KEYS.activeMailbox) ?? ""
}

export function WorkspaceProvider({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient()
  const [savedAddresses, setSavedAddresses] = React.useState<string[]>(readSavedAddresses)
  const [activeAddressState, setActiveAddressState] = React.useState(readActiveAddress)
  const initializedActiveRef = React.useRef(false)

  const domainsQuery = useQuery({
    queryKey: queryKeys.domains,
    queryFn: apiClient.domains,
    staleTime: 5 * 60_000,
    retry: 1,
  })

  const workersQuery = useQuery({
    queryKey: queryKeys.workers,
    queryFn: apiClient.workers,
    staleTime: 5 * 60_000,
    retry: 1,
  })

  const summaryQuery = useQuery({
    queryKey: queryKeys.inboxSummary,
    queryFn: apiClient.inboxSummary,
    staleTime: 30_000,
    refetchInterval: 60_000,
    retry: 1,
  })

  const latestQuery = useQuery({
    queryKey: queryKeys.latestAddress,
    queryFn: apiClient.latestAddress,
    staleTime: 60_000,
    retry: 1,
  })

  const configQuery = useQuery({
    queryKey: queryKeys.config,
    queryFn: apiClient.config,
    staleTime: 5 * 60_000,
    retry: 1,
  })

  const healthQuery = useQuery({
    queryKey: queryKeys.health,
    queryFn: apiClient.health,
    staleTime: 60_000,
    refetchInterval: 120_000,
    retry: 0,
  })

  const sessionQuery = useQuery({
    queryKey: queryKeys.session,
    queryFn: apiClient.session,
    staleTime: 5 * 60_000,
    retry: 0,
  })

  React.useEffect(() => {
    if (initializedActiveRef.current) return
    if (!latestQuery.isFetched) return

    const stored = localStorage.getItem(STORAGE_KEYS.activeMailbox)
    if (stored !== null) {
      initializedActiveRef.current = true
      return
    }

    const latest = latestQuery.data?.address
    if (latest) {
      const normalized = normalizeAddress(latest)
      setActiveAddressState(normalized)
      localStorage.setItem(STORAGE_KEYS.activeMailbox, normalized)
    }
    initializedActiveRef.current = true
  }, [latestQuery.data, latestQuery.isFetched])

  const setActiveAddress = React.useCallback((address: string) => {
    const normalized = address ? normalizeAddress(address) : ""
    setActiveAddressState(normalized)
    if (normalized) {
      localStorage.setItem(STORAGE_KEYS.activeMailbox, normalized)
    } else {
      localStorage.removeItem(STORAGE_KEYS.activeMailbox)
    }
  }, [])

  const addSavedAddress = React.useCallback((address: string) => {
    const normalized = normalizeAddress(address)
    if (!normalized) return
    setSavedAddresses((current) => {
      if (current.includes(normalized)) return current
      const next = [normalized, ...current].slice(0, 100)
      localStorage.setItem(STORAGE_KEYS.savedAddresses, JSON.stringify(next))
      return next
    })
  }, [])

  const removeSavedAddress = React.useCallback((address: string) => {
    const normalized = normalizeAddress(address)
    setSavedAddresses((current) => {
      const next = current.filter((item) => item !== normalized)
      localStorage.setItem(STORAGE_KEYS.savedAddresses, JSON.stringify(next))
      return next
    })
    setActiveAddressState((current) => {
      if (current !== normalized) return current
      localStorage.removeItem(STORAGE_KEYS.activeMailbox)
      return ""
    })
  }, [])

  const refreshWorkspace = React.useCallback(async () => {
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: queryKeys.domains }),
      queryClient.invalidateQueries({ queryKey: queryKeys.workers }),
      queryClient.invalidateQueries({ queryKey: queryKeys.inboxSummary }),
      queryClient.invalidateQueries({ queryKey: queryKeys.latestAddress }),
      queryClient.invalidateQueries({ queryKey: queryKeys.config }),
      queryClient.invalidateQueries({ queryKey: queryKeys.health }),
      queryClient.invalidateQueries({ queryKey: ["inbox"] }),
    ])
  }, [queryClient])

  const isAddressSaved = React.useCallback(
    (address: string) => savedAddresses.includes(normalizeAddress(address)),
    [savedAddresses]
  )

  const summary = React.useMemo(() => summaryQuery.data ?? [], [summaryQuery.data])
  const latestAddress = latestQuery.data ?? null

  const addresses = React.useMemo(() => {
    const map = new Map<string, Mailbox>()

    const ensure = (address: string): Mailbox | null => {
      const normalized = normalizeAddress(address)
      if (!normalized || !normalized.includes("@")) return null
      const existing = map.get(normalized)
      if (existing) return existing
      const [localPart, domain] = normalized.split("@")
      const created: Mailbox = {
        address: normalized,
        localPart: localPart ?? normalized,
        domain: domain ?? "",
        total: 0,
        latestAt: null,
        saved: savedAddresses.includes(normalized),
      }
      map.set(normalized, created)
      return created
    }

    for (const row of summary) {
      const item = ensure(row.recipient)
      if (!item) continue
      item.total = Number(row.total) || 0
      item.latestAt = row.latest_at
    }

    for (const address of savedAddresses) ensure(address)
    if (latestAddress?.address) ensure(latestAddress.address)
    if (activeAddressState) ensure(activeAddressState)

    return Array.from(map.values()).sort((left, right) => {
      const leftTime = left.latestAt ? new Date(left.latestAt).getTime() : 0
      const rightTime = right.latestAt ? new Date(right.latestAt).getTime() : 0
      if (rightTime !== leftTime) return rightTime - leftTime
      return left.address.localeCompare(right.address)
    })
  }, [summary, savedAddresses, latestAddress, activeAddressState])

  const totalMessages = React.useMemo(
    () => summary.reduce((total, row) => total + (Number(row.total) || 0), 0),
    [summary]
  )

  const activeAddress = activeAddressState || null

  const value = React.useMemo<WorkspaceContextValue>(
    () => ({
      domains: domainsQuery.data ?? [],
      workers: workersQuery.data ?? [],
      summary,
      latestAddress,
      config: configQuery.data,
      health: healthQuery.data,
      healthError: healthQuery.error as Error | null,
      session: sessionQuery.data,
      addresses,
      savedAddresses,
      activeAddress,
      totalMessages,
      mailboxCount: addresses.length,
      domainsLoading: domainsQuery.isLoading,
      domainsError: domainsQuery.error as Error | null,
      summaryLoading: summaryQuery.isLoading,
      summaryError: summaryQuery.error as Error | null,
      setActiveAddress,
      addSavedAddress,
      removeSavedAddress,
      refreshWorkspace,
      isAddressSaved,
    }),
    [
      domainsQuery.data,
      domainsQuery.isLoading,
      domainsQuery.error,
      workersQuery.data,
      summary,
      latestAddress,
      configQuery.data,
      healthQuery.data,
      healthQuery.error,
      sessionQuery.data,
      addresses,
      savedAddresses,
      activeAddress,
      totalMessages,
      summaryQuery.isLoading,
      summaryQuery.error,
      setActiveAddress,
      addSavedAddress,
      removeSavedAddress,
      refreshWorkspace,
      isAddressSaved,
    ]
  )

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>
}

export function useWorkspace() {
  const context = React.useContext(WorkspaceContext)
  if (!context) throw new Error("useWorkspace must be used within WorkspaceProvider")
  return context
}
