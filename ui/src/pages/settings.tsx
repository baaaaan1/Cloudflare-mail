import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  Check,
  CircleAlert,
  CircleCheck,
  CircleX,
  Copy,
  Database,
  Eye,
  EyeOff,
  Gauge,
  KeyRound,
  Loader2,
  LockKeyhole,
  Monitor,
  Moon,
  Palette,
  RefreshCw,
  Settings2,
  ShieldCheck,
  Sun,
  Trash2,
  Wand2,
} from "lucide-react"
import { motion } from "motion/react"
import { toast } from "sonner"

import { PageHeader } from "@/components/page-header"
import { useTheme } from "@/components/theme-provider"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useWorkspace } from "@/hooks/use-workspace"
import { apiClient } from "@/lib/api"
import { ACCENT_PRESETS, APP_VERSION } from "@/lib/constants"
import { copyText } from "@/lib/format"
import { queryKeys, STORAGE_KEYS } from "@/lib/query-keys"
import type { ConfigPayload, Diagnostics } from "@/lib/types"
import { cn } from "cn"

function SecretInput({
  id,
  value,
  onChange,
  placeholder,
}: {
  id: string
  value: string
  onChange: (value: string) => void
  placeholder: string
}) {
  const [visible, setVisible] = React.useState(false)
  return (
    <div className="relative">
      <Input
        id={id}
        type={visible ? "text" : "password"}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="pr-10 font-mono text-[12px]"
        autoComplete="off"
        spellCheck={false}
      />
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        className="absolute top-1/2 right-1 -translate-y-1/2"
        onClick={() => setVisible((current) => !current)}
        aria-label={visible ? "Hide value" : "Show value"}
      >
        {visible ? <EyeOff /> : <Eye />}
      </Button>
    </div>
  )
}

function CopyField({
  value,
  label,
  onCopied,
}: {
  value: string
  label: string
  onCopied: () => void
}) {
  if (!value) return null
  return (
    <Button variant="ghost" size="icon-sm" onClick={onCopied} aria-label={`Copy ${label}`}>
      <Copy />
    </Button>
  )
}

export function SettingsPage() {
  const queryClient = useQueryClient()
  const { config, health, refreshWorkspace } = useWorkspace()
  const theme = useTheme()

  const [accountId, setAccountId] = React.useState("")
  const [d1Id, setD1Id] = React.useState("")
  const [apiToken, setApiToken] = React.useState("")
  const [adminToken, setAdminToken] = React.useState("")
  const [diagnostics, setDiagnostics] = React.useState<Diagnostics | null>(null)
  const [customHex, setCustomHex] = React.useState(theme.customAccent || "#0d9488")
  const [resetOpen, setResetOpen] = React.useState(false)

  const configQuery = useQuery({
    queryKey: queryKeys.config,
    queryFn: apiClient.config,
    staleTime: 5 * 60_000,
    retry: 1,
  })

  React.useEffect(() => {
    if (!configQuery.data) return
    setAccountId(configQuery.data.account_id || "")
    setD1Id(configQuery.data.d1_database_id || "")
  }, [configQuery.data])

  const saveConfig = useMutation({
    mutationFn: (payload: ConfigPayload) => apiClient.saveConfig(payload),
    onSuccess: async () => {
      toast.success("Settings saved")
      setApiToken("")
      setAdminToken("")
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.config }),
        queryClient.invalidateQueries({ queryKey: queryKeys.domains }),
        queryClient.invalidateQueries({ queryKey: queryKeys.workers }),
        queryClient.invalidateQueries({ queryKey: queryKeys.health }),
        queryClient.invalidateQueries({ queryKey: queryKeys.destinations }),
      ])
    },
    onError: (error: Error) => {
      toast.error("Could not save settings", { description: error.message })
    },
  })

  const diagnosticsMutation = useMutation({
    mutationFn: apiClient.diagnostics,
    onSuccess: (data) => setDiagnostics(data),
    onError: (error: Error) => {
      toast.error("Diagnostics failed", { description: error.message })
    },
  })

  const initInbox = useMutation({
    mutationFn: apiClient.initInbox,
    onSuccess: () => {
      toast.success("D1 schema initialized")
      void queryClient.invalidateQueries({ queryKey: queryKeys.inboxSummary })
    },
    onError: (error: Error) => {
      toast.error("Could not initialize D1", { description: error.message })
    },
  })

  const submitConfig = (event: React.FormEvent) => {
    event.preventDefault()
    const payload: ConfigPayload = {
      account_id: accountId.trim(),
      d1_database_id: d1Id.trim(),
    }
    if (apiToken.trim()) payload.api_token = apiToken.trim()
    if (adminToken.trim()) payload.admin_api_token = adminToken.trim()
    saveConfig.mutate(payload)
  }

  const copyValue = (value: string, label: string) => {
    void copyText(value)
      .then(() => toast.success(`${label} copied`))
      .catch(() => toast.error("Could not copy"))
  }

  const handleResetLocal = () => {
    localStorage.removeItem(STORAGE_KEYS.savedAddresses)
    localStorage.removeItem(STORAGE_KEYS.activeMailbox)
    localStorage.removeItem(STORAGE_KEYS.readMessages)
    localStorage.removeItem(STORAGE_KEYS.nameStyle)
    setResetOpen(false)
    toast.success("Local data cleared")
    window.setTimeout(() => window.location.reload(), 400)
  }

  const checks = diagnostics?.checks ?? []
  const passed = checks.filter((check) => check.ok).length
  const progress = checks.length ? (passed / checks.length) * 100 : 0

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Settings"
        title="Workspace settings"
        description="Connect Cloudflare, tune the appearance, and inspect every integration before you rely on it."
        actions={
          <Button variant="outline" onClick={() => void refreshWorkspace()}>
            <RefreshCw />
            Refresh data
          </Button>
        }
      />

      <Tabs defaultValue="general" className="gap-5">
        <TabsList className="h-10 w-full justify-start gap-1 overflow-x-auto rounded-xl bg-muted/60 p-1 sm:w-fit">
          <TabsTrigger value="general" className="gap-1.5 px-3">
            <KeyRound />
            General
          </TabsTrigger>
          <TabsTrigger value="appearance" className="gap-1.5 px-3">
            <Palette />
            Appearance
          </TabsTrigger>
          <TabsTrigger value="diagnostics" className="gap-1.5 px-3">
            <Gauge />
            Diagnostics
          </TabsTrigger>
          <TabsTrigger value="advanced" className="gap-1.5 px-3">
            <Settings2 />
            Advanced
          </TabsTrigger>
        </TabsList>

        <TabsContent value="general" className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-[1.2fr_0.8fr]">
            <form onSubmit={submitConfig} className="surface-card overflow-hidden rounded-2xl">
              <div className="border-b border-border/60 px-5 py-4">
                <h2 className="text-sm font-semibold">Cloudflare credentials</h2>
                <p className="mt-0.5 text-[11px] text-muted-foreground">
                  Stored in the panel&apos;s <span className="font-mono">.env</span>. Tokens are
                  never displayed after saving.
                </p>
              </div>

              <div className="space-y-4 p-5">
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="account-id">Account ID</Label>
                    <div className="flex items-center gap-1.5">
                      <Badge variant={config?.account_id ? "secondary" : "destructive"} className="text-[10px]">
                        {config?.account_id ? "Configured" : "Missing"}
                      </Badge>
                      <CopyField
                        value={accountId}
                        label="account ID"
                        onCopied={() => copyValue(accountId, "Account ID")}
                      />
                    </div>
                  </div>
                  <Input
                    id="account-id"
                    value={accountId}
                    onChange={(event) => setAccountId(event.target.value)}
                    placeholder="Cloudflare account ID"
                    className="font-mono text-[12px]"
                    spellCheck={false}
                  />
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="d1-id">D1 database ID</Label>
                    <div className="flex items-center gap-1.5">
                      <Badge variant={config?.d1_database_id ? "secondary" : "outline"} className="text-[10px]">
                        {config?.d1_database_id ? "Configured" : "Optional"}
                      </Badge>
                      <CopyField
                        value={d1Id}
                        label="D1 database ID"
                        onCopied={() => copyValue(d1Id, "D1 database ID")}
                      />
                    </div>
                  </div>
                  <Input
                    id="d1-id"
                    value={d1Id}
                    onChange={(event) => setD1Id(event.target.value)}
                    placeholder="D1 database ID"
                    className="font-mono text-[12px]"
                    spellCheck={false}
                  />
                  <p className="text-[10px] text-muted-foreground">
                    Required for storing and reading the inbox. Create one with{" "}
                    <span className="font-mono">npm run cf:setup</span>.
                  </p>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="api-token">Cloudflare API token</Label>
                    <Badge variant={config?.has_token ? "secondary" : "destructive"} className="text-[10px]">
                      {config?.has_token ? "Configured" : "Missing"}
                    </Badge>
                  </div>
                  <SecretInput
                    id="api-token"
                    value={apiToken}
                    onChange={setApiToken}
                    placeholder={
                      config?.has_token ? "•••••••• (leave blank to keep)" : "Paste your API token"
                    }
                  />
                  <p className="text-[10px] text-muted-foreground">
                    Needs Account D1 Read, Workers Scripts Edit, and Zone Email Routing Edit.
                  </p>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="admin-token">Legacy admin token</Label>
                    <Badge
                      variant={config?.has_admin_api_token ? "secondary" : "outline"}
                      className="text-[10px]"
                    >
                      {config?.has_admin_api_token ? "Configured" : "Optional"}
                    </Badge>
                  </div>
                  <SecretInput
                    id="admin-token"
                    value={adminToken}
                    onChange={setAdminToken}
                    placeholder={
                      config?.has_admin_api_token
                        ? "•••••••• (leave blank to keep)"
                        : "Kept for backward compatibility"
                    }
                  />
                  <p className="text-[10px] text-muted-foreground">
                    REST API access is managed with scoped keys on the{" "}
                    <span className="font-mono">API docs</span> page.
                  </p>
                </div>

                <div className="flex justify-end pt-1">
                  <Button type="submit" disabled={saveConfig.isPending}>
                    {saveConfig.isPending ? <Loader2 className="animate-spin" /> : <Check />}
                    {saveConfig.isPending ? "Saving…" : "Save credentials"}
                  </Button>
                </div>
              </div>
            </form>

            <div className="space-y-4">
              <div className="surface-card rounded-2xl p-5">
                <div className="flex items-center gap-2">
                  <div className="grid size-9 place-items-center rounded-xl bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                    <ShieldCheck className="size-4" />
                  </div>
                  <div>
                    <h2 className="text-sm font-semibold">Panel access</h2>
                    <p className="text-[11px] text-muted-foreground">Password-only session</p>
                  </div>
                </div>
                <div className="mt-4 space-y-3 text-[11px]">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-muted-foreground">Authentication</span>
                    <span className="font-medium">Password + signed cookie</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-muted-foreground">Session lifetime</span>
                    <span className="font-medium">7 days</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-muted-foreground">Rate limiting</span>
                    <span className="font-medium">5 attempts / minute</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-muted-foreground">Lockout</span>
                    <span className="font-medium">15 min, escalating to 24 h</span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-muted-foreground">Captcha</span>
                    <span className="font-medium">Turnstile (optional)</span>
                  </div>
                </div>
                <div className="mt-4 rounded-xl border border-border/70 bg-muted/30 p-3 text-[10px] leading-relaxed text-muted-foreground">
                  Change <span className="font-mono">APP_PASSWORD</span> in{" "}
                  <span className="font-mono">.env</span> and restart the container to rotate the
                  password.
                </div>
              </div>

              <div className="surface-card rounded-2xl p-5">
                <div className="flex items-center gap-2">
                  <div className="grid size-9 place-items-center rounded-xl bg-primary/10 text-primary">
                    <Database className="size-4" />
                  </div>
                  <div>
                    <h2 className="text-sm font-semibold">Connection status</h2>
                    <p className="text-[11px] text-muted-foreground">
                      {health?.ok ? "Cloudflare API reachable" : "Check credentials"}
                    </p>
                  </div>
                </div>
                <div className="mt-4 space-y-2.5">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-muted-foreground">API health</span>
                    <Badge
                      variant="secondary"
                      className={cn(
                        health?.ok
                          ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                          : "bg-amber-500/10 text-amber-700 dark:text-amber-300"
                      )}
                    >
                      {health?.ok ? "Healthy" : "Attention"}
                    </Badge>
                  </div>
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-muted-foreground">Destinations</span>
                    <span className="font-medium tabular-nums">{health?.destinations ?? "—"}</span>
                  </div>
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="text-muted-foreground">Warnings</span>
                    <span className="font-medium tabular-nums">{health?.warnings.length ?? 0}</span>
                  </div>
                </div>
                {health?.warnings.length ? (
                  <ul className="mt-3 space-y-1 rounded-xl border border-amber-500/20 bg-amber-500/5 p-2.5 text-[10px] text-amber-700 dark:text-amber-300">
                    {health.warnings.map((warning) => (
                      <li key={warning} className="break-words">
                        {warning}
                      </li>
                    ))}
                  </ul>
                ) : null}
              </div>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="appearance" className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
            <div className="surface-card rounded-2xl p-5">
              <h2 className="text-sm font-semibold">Theme</h2>
              <p className="mt-0.5 text-[11px] text-muted-foreground">
                Choose how the panel looks. System follows your OS preference.
              </p>
              <div className="mt-4 grid grid-cols-3 gap-2">
                {(
                  [
                    { value: "light", label: "Light", icon: Sun },
                    { value: "dark", label: "Dark", icon: Moon },
                    { value: "system", label: "System", icon: Monitor },
                  ] as const
                ).map((option) => {
                  const Icon = option.icon
                  const active = theme.theme === option.value
                  return (
                    <button
                      key={option.value}
                      type="button"
                      onClick={() => theme.setTheme(option.value)}
                      className={cn(
                        "flex flex-col items-center gap-2 rounded-xl border p-4 text-xs font-medium transition-colors",
                        active
                          ? "border-primary/30 bg-primary/8 text-primary"
                          : "border-border/70 text-muted-foreground hover:bg-muted/50 hover:text-foreground"
                      )}
                    >
                      <Icon className="size-5" />
                      {option.label}
                      {active && <Check className="size-3" />}
                    </button>
                  )
                })}
              </div>

              <div className="mt-6">
                <h2 className="text-sm font-semibold">Accent color</h2>
                <p className="mt-0.5 text-[11px] text-muted-foreground">
                  Drives buttons, active states, and highlights across the panel.
                </p>
                <div className="mt-3 flex flex-wrap gap-2.5">
                  {ACCENT_PRESETS.map((preset) => {
                    const active = theme.accentId === preset.id
                    return (
                      <motion.button
                        key={preset.id}
                        type="button"
                        onClick={() => theme.setAccent(preset.id)}
                        whileHover={{ scale: 1.08 }}
                        whileTap={{ scale: 0.95 }}
                        className={cn(
                          "relative grid size-9 place-items-center rounded-full ring-offset-2 ring-offset-card",
                          active ? "ring-2 ring-foreground/40" : "ring-1 ring-black/5"
                        )}
                        style={{ backgroundColor: preset.swatch }}
                        aria-label={preset.name}
                        aria-pressed={active}
                      >
                        {active && <Check className="size-4 text-white drop-shadow" />}
                      </motion.button>
                    )
                  })}
                </div>

                <div className="mt-4 flex flex-col gap-2 rounded-xl border border-border/70 bg-muted/25 p-3 sm:flex-row sm:items-end">
                  <div className="space-y-1.5">
                    <Label htmlFor="custom-accent" className="text-[11px]">
                      Custom color
                    </Label>
                    <div className="flex items-center gap-2">
                      <input
                        id="custom-accent"
                        type="color"
                        value={customHex}
                        onChange={(event) => setCustomHex(event.target.value)}
                        className="h-9 w-12 cursor-pointer rounded-lg border border-border bg-transparent p-1"
                      />
                      <Input
                        value={customHex}
                        onChange={(event) => setCustomHex(event.target.value)}
                        className="h-9 w-28 font-mono text-[12px]"
                        aria-label="Custom accent hex"
                      />
                    </div>
                  </div>
                  <Button
                    type="button"
                    variant="outline"
                    className="sm:ml-auto"
                    onClick={() => theme.setCustomAccent(customHex)}
                  >
                    <Wand2 />
                    Apply
                  </Button>
                </div>
              </div>
            </div>

            <div className="surface-card overflow-hidden rounded-2xl">
              <div className="border-b border-border/60 px-5 py-4">
                <h2 className="text-sm font-semibold">Live preview</h2>
                <p className="mt-0.5 text-[11px] text-muted-foreground">
                  A small sample of the current design tokens.
                </p>
              </div>
              <div className="space-y-4 p-5">
                <div className="rounded-2xl border border-border/70 bg-muted/25 p-4">
                  <div className="flex items-center gap-2">
                    <span className="signal-dot" />
                    <span className="text-[11px] font-medium">Inbox connected</span>
                    <Badge variant="secondary" className="ml-auto bg-primary/10 text-primary">
                      Live
                    </Badge>
                  </div>
                  <p className="mt-3 font-mono text-xs text-muted-foreground">
                    hello.world@your-domain.com
                  </p>
                  <div className="mt-4 flex gap-2">
                    <Button size="sm">
                      <Check />
                      Primary
                    </Button>
                    <Button size="sm" variant="outline">
                      Secondary
                    </Button>
                    <Button size="sm" variant="ghost">
                      Ghost
                    </Button>
                  </div>
                </div>
                <div className="grid grid-cols-3 gap-2">
                  {["bg-primary", "bg-chart-2", "bg-chart-3", "bg-chart-4", "bg-chart-5", "bg-muted"].map(
                    (className) => (
                      <div
                        key={className}
                        className={cn("h-12 rounded-xl border border-border/50", className)}
                      />
                    )
                  )}
                </div>
                <p className="text-[10px] leading-relaxed text-muted-foreground">
                  Press <kbd className="rounded border border-border bg-muted/60 px-1 py-0.5 font-mono">D</kbd>{" "}
                  anywhere to toggle light and dark mode.
                </p>
              </div>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="diagnostics" className="space-y-4">
          <div className="surface-card rounded-2xl p-5">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-sm font-semibold">Cloudflare diagnostics</h2>
                <p className="mt-0.5 text-[11px] text-muted-foreground">
                  Probes token validity, destinations, rules, domains, and D1 access.
                </p>
              </div>
              <Button
                onClick={() => diagnosticsMutation.mutate()}
                disabled={diagnosticsMutation.isPending}
              >
                {diagnosticsMutation.isPending ? <Loader2 className="animate-spin" /> : <Gauge />}
                {diagnosticsMutation.isPending ? "Running…" : "Run diagnostics"}
              </Button>
            </div>

            {diagnostics ? (
              <>
                <div className="mt-4 flex items-center gap-3">
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                    <motion.div
                      className={cn(
                        "h-full rounded-full",
                        diagnostics.ok ? "bg-emerald-500" : "bg-amber-500"
                      )}
                      initial={{ width: 0 }}
                      animate={{ width: `${progress}%` }}
                      transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
                    />
                  </div>
                  <span className="text-[11px] font-medium tabular-nums">
                    {passed}/{checks.length}
                  </span>
                </div>
                <div className="mt-4 space-y-2">
                  {checks.map((check) => (
                    <div
                      key={check.name}
                      className={cn(
                        "rounded-xl border p-3",
                        check.ok
                          ? "border-emerald-500/20 bg-emerald-500/5"
                          : "border-destructive/20 bg-destructive/5"
                      )}
                    >
                      <div className="flex items-start gap-2.5">
                        <span
                          className={cn(
                            "mt-0.5 grid size-6 shrink-0 place-items-center rounded-full",
                            check.ok
                              ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                              : "bg-destructive/10 text-destructive"
                          )}
                        >
                          {check.ok ? (
                            <CircleCheck className="size-3.5" />
                          ) : (
                            <CircleX className="size-3.5" />
                          )}
                        </span>
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="text-[12px] font-medium capitalize">
                              {check.name.replace(/_/g, " ")}
                            </span>
                            <Badge
                              variant="secondary"
                              className={cn(
                                "text-[10px]",
                                check.ok
                                  ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                                  : "bg-destructive/10 text-destructive"
                              )}
                            >
                              {check.ok ? "Pass" : "Fail"}
                            </Badge>
                          </div>
                          <p className="mt-1 text-[10px] break-words text-muted-foreground">
                            {check.detail}
                          </p>
                          {!check.ok && check.hint && (
                            <p className="mt-1.5 rounded-lg bg-background/60 p-2 text-[10px] leading-relaxed text-amber-700 dark:text-amber-300">
                              {check.hint}
                            </p>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="mt-4 flex flex-col items-center justify-center rounded-xl border border-dashed border-border/80 px-6 py-10 text-center">
                <div className="grid size-11 place-items-center rounded-xl bg-muted/60 text-muted-foreground">
                  <Gauge className="size-5" />
                </div>
                <p className="mt-3 text-sm font-medium">No diagnostics yet</p>
                <p className="mt-1 max-w-sm text-xs text-muted-foreground">
                  Run a probe to see exactly which Cloudflare permissions are working.
                </p>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="advanced" className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="surface-card rounded-2xl p-5">
              <div className="flex items-start gap-3">
                <div className="grid size-9 shrink-0 place-items-center rounded-xl bg-primary/10 text-primary">
                  <Database className="size-4" />
                </div>
                <div>
                  <h2 className="text-sm font-semibold">D1 inbox schema</h2>
                  <p className="mt-0.5 text-[11px] text-muted-foreground">
                    Create the <span className="font-mono">emails</span> and{" "}
                    <span className="font-mono">generated_addresses</span> tables if they are
                    missing.
                  </p>
                </div>
              </div>
              <div className="mt-4 flex flex-wrap gap-2">
                <Button
                  variant="outline"
                  onClick={() => initInbox.mutate()}
                  disabled={initInbox.isPending}
                >
                  {initInbox.isPending ? <Loader2 className="animate-spin" /> : <Database />}
                  Initialize schema
                </Button>
                <Button variant="ghost" onClick={() => void refreshWorkspace()}>
                  <RefreshCw />
                  Refresh caches
                </Button>
              </div>
            </div>

            <div className="surface-card rounded-2xl p-5">
              <div className="flex items-start gap-3">
                <div className="grid size-9 shrink-0 place-items-center rounded-xl bg-amber-500/10 text-amber-600 dark:text-amber-400">
                  <Trash2 className="size-4" />
                </div>
                <div>
                  <h2 className="text-sm font-semibold">Local browser data</h2>
                  <p className="mt-0.5 text-[11px] text-muted-foreground">
                    Saved bookmarks, read state, and the active mailbox live in this browser only.
                  </p>
                </div>
              </div>
              <div className="mt-4">
                <Button variant="outline" onClick={() => setResetOpen(true)}>
                  <Trash2 />
                  Clear local data
                </Button>
              </div>
            </div>
          </div>

          <div className="surface-card rounded-2xl p-5">
            <div className="flex items-center gap-2">
              <div className="grid size-9 place-items-center rounded-xl bg-muted text-muted-foreground">
                <LockKeyhole className="size-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold">About this build</h2>
                <p className="text-[11px] text-muted-foreground">
                  Cloudflare Email Panel · React + shadcn/ui
                </p>
              </div>
              <Badge variant="secondary" className="ml-auto">
                v{APP_VERSION}
              </Badge>
            </div>
            <div className="mt-4 grid gap-3 text-[11px] sm:grid-cols-3">
              <div className="rounded-xl border border-border/70 bg-muted/25 p-3">
                <p className="text-muted-foreground">Frontend</p>
                <p className="mt-1 font-medium">React 19 + Vite</p>
              </div>
              <div className="rounded-xl border border-border/70 bg-muted/25 p-3">
                <p className="text-muted-foreground">Design system</p>
                <p className="mt-1 font-medium">shadcn/ui + Tailwind 4</p>
              </div>
              <div className="rounded-xl border border-border/70 bg-muted/25 p-3">
                <p className="text-muted-foreground">Motion</p>
                <p className="mt-1 font-medium">Motion + reduced-motion aware</p>
              </div>
            </div>
            <div className="mt-4 flex items-start gap-2 rounded-xl border border-border/70 bg-muted/20 p-3 text-[10px] leading-relaxed text-muted-foreground">
              <CircleAlert className="mt-0.5 size-3.5 shrink-0" />
              <p>
                Credentials saved here are written to <span className="font-mono">.env</span>. In
                Dokploy or other platforms that regenerate env files, set values in the platform
                UI instead.
              </p>
            </div>
          </div>
        </TabsContent>
      </Tabs>

      <AlertDialog open={resetOpen} onOpenChange={setResetOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Clear local browser data?</AlertDialogTitle>
            <AlertDialogDescription>
              This removes saved address bookmarks, the active mailbox selection, name style, and
              read state from this browser. Mail and routing rules are untouched.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleResetLocal}
              className="bg-destructive text-white hover:bg-destructive/90"
            >
              <Trash2 />
              Clear and reload
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

