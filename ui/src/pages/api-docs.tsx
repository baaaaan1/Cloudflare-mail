import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  BookOpen,
  Braces,
  Check,
  CircleAlert,
  Copy,
  Inbox,
  KeyRound,
  Loader2,
  LockKeyhole,
  Plus,
  Route,
  ShieldCheck,
  Terminal,
  Trash2,
  Zap,
} from "lucide-react"
import { toast } from "sonner"

import { EmptyState } from "@/components/empty-state"
import { ErrorState } from "@/components/error-state"
import { PageHeader } from "@/components/page-header"
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { apiClient } from "@/lib/api"
import { copyText, formatDateTime } from "@/lib/format"
import { queryKeys } from "@/lib/query-keys"
import type { ApiKey, CreatedApiKey } from "@/lib/types"
import { cn } from "cn"

type HttpMethod = "GET" | "POST" | "PUT" | "DELETE"

type Endpoint = {
  method: HttpMethod
  path: string
  description: string
  scope: string
  body?: string
  query?: string
}

type EndpointGroup = {
  name: string
  description: string
  endpoints: Endpoint[]
}

const ENDPOINT_GROUPS: EndpointGroup[] = [
  {
    name: "Destinations",
    description: "Forwarding addresses verified at the Cloudflare account level.",
    endpoints: [
      {
        method: "GET",
        path: "/api/destinations",
        description: "List every destination in the account.",
        scope: "destinations:read",
      },
      {
        method: "POST",
        path: "/api/destinations",
        description: "Create a destination and trigger Cloudflare verification.",
        scope: "destinations:write",
        body: '{ "email": "you@example.com" }',
      },
      {
        method: "DELETE",
        path: "/api/destinations/:id",
        description: "Delete a destination by ID.",
        scope: "destinations:write",
      },
    ],
  },
  {
    name: "Domains and workers",
    description: "Zones and Worker scripts available to the configured account.",
    endpoints: [
      {
        method: "GET",
        path: "/api/domains",
        description: "List zones in the account (cached for five minutes).",
        scope: "domains:read",
      },
      {
        method: "GET",
        path: "/api/workers",
        description: "List Worker scripts (cached for five minutes).",
        scope: "domains:read",
      },
    ],
  },
  {
    name: "Routing rules",
    description: "Literal email routing rules per zone.",
    endpoints: [
      {
        method: "GET",
        path: "/api/rules",
        description: "List rules for a zone.",
        scope: "rules:read",
        query: "zoneId=<zone-id>",
      },
      {
        method: "POST",
        path: "/api/rules",
        description: "Create a literal routing rule.",
        scope: "rules:write",
        body: `{
  "zoneId": "<zone-id>",
  "customEmail": "hello@example.com",
  "type": "worker",
  "destinationId": "inbox-worker"
}`,
      },
      {
        method: "PUT",
        path: "/api/rules/:id",
        description: "Update a rule, including enable/disable.",
        scope: "rules:write",
        body: `{
  "zoneId": "<zone-id>",
  "enabled": false
}`,
      },
      {
        method: "DELETE",
        path: "/api/rules/:id",
        description: "Delete a rule. Send the zone in the body or query.",
        scope: "rules:write",
        query: "zoneId=<zone-id>",
      },
    ],
  },
  {
    name: "Catch-all",
    description: "The zone-level catch-all rule.",
    endpoints: [
      {
        method: "POST",
        path: "/api/catch-all",
        description: "Forward, drop, disable, or route catch-all mail to a worker.",
        scope: "rules:write",
        body: `{
  "zoneId": "<zone-id>",
  "action": "forward",
  "destinationId": "you@example.com"
}`,
      },
    ],
  },
  {
    name: "Generated addresses",
    description: "Temporary addresses kept for seven days in D1.",
    endpoints: [
      {
        method: "POST",
        path: "/api/addresses",
        description: "Save or refresh a generated address.",
        scope: "inbox:write",
        body: '{ "address": "alias@example.com" }',
      },
      {
        method: "GET",
        path: "/api/addresses/latest",
        description: "Read the most recently generated address.",
        scope: "inbox:read",
      },
    ],
  },
  {
    name: "Inbox",
    description: "Messages stored in the D1 database.",
    endpoints: [
      {
        method: "GET",
        path: "/api/inbox/summary",
        description: "Per-recipient totals with first and latest timestamps.",
        scope: "inbox:read",
      },
      {
        method: "GET",
        path: "/api/inbox",
        description: "List message summaries, newest first.",
        scope: "inbox:read",
        query: "limit=50&offset=0&recipients=a@x.com,b@x.com",
      },
      {
        method: "GET",
        path: "/api/inbox/:id",
        description: "Read a full message including text and HTML bodies.",
        scope: "inbox:read",
      },
      {
        method: "DELETE",
        path: "/api/inbox/:id",
        description: "Delete a message.",
        scope: "inbox:write",
      },
      {
        method: "POST",
        path: "/api/inbox/init",
        description: "Create the D1 tables if they are missing.",
        scope: "inbox:write",
      },
    ],
  },
  {
    name: "Config and diagnostics",
    description: "Panel configuration and Cloudflare connectivity probes.",
    endpoints: [
      {
        method: "GET",
        path: "/api/config",
        description: "Read the account ID, D1 ID, and credential status.",
        scope: "config:read",
      },
      {
        method: "POST",
        path: "/api/config",
        description: "Update credentials stored in .env.",
        scope: "config:write",
        body: `{
  "account_id": "<account-id>",
  "d1_database_id": "<database-id>",
  "api_token": "<token>"
}`,
      },
      {
        method: "GET",
        path: "/api/diagnostics",
        description: "Probe token, destinations, rules, domains, and D1.",
        scope: "config:read",
      },
    ],
  },
  {
    name: "API keys",
    description: "Manage keys. Plaintext is only returned on creation.",
    endpoints: [
      {
        method: "GET",
        path: "/api/keys",
        description: "List keys. Scoped keys only see themselves.",
        scope: "keys:read",
      },
      {
        method: "POST",
        path: "/api/keys",
        description: "Create a key with a set of scopes.",
        scope: "keys:write",
        body: `{
  "name": "ci-deploy",
  "scopes": ["rules:read", "destinations:read"]
}`,
      },
      {
        method: "DELETE",
        path: "/api/keys/:id",
        description: "Revoke a key.",
        scope: "keys:write",
      },
    ],
  },
]

const SCOPE_GROUPS: { label: string; scopes: { value: string; description: string }[] }[] = [
  {
    label: "Routing",
    scopes: [
      { value: "rules:read", description: "List rules and catch-all state" },
      { value: "rules:write", description: "Create, update, delete rules and catch-all" },
    ],
  },
  {
    label: "Destinations",
    scopes: [
      { value: "destinations:read", description: "List forwarding destinations" },
      { value: "destinations:write", description: "Create and delete destinations" },
    ],
  },
  {
    label: "Inbox",
    scopes: [
      { value: "inbox:read", description: "Read messages and generated addresses" },
      { value: "inbox:write", description: "Delete messages and save addresses" },
    ],
  },
  {
    label: "Workspace",
    scopes: [
      { value: "domains:read", description: "List zones and workers" },
      { value: "config:read", description: "Read config and run diagnostics" },
      { value: "config:write", description: "Update Cloudflare credentials" },
      { value: "keys:read", description: "List API keys" },
      { value: "keys:write", description: "Create and revoke API keys" },
    ],
  },
]

const ALL_SCOPES = SCOPE_GROUPS.flatMap((group) => group.scopes.map((scope) => scope.value))
const READ_SCOPES = ALL_SCOPES.filter((scope) => scope.endsWith(":read"))

type KeyTemplate = {
  id: string
  name: string
  defaultName: string
  description: string
  scopes: string[]
  icon: React.ComponentType<{ className?: string }>
}

const KEY_TEMPLATES: KeyTemplate[] = [
  {
    id: "address-inbox",
    name: "Address + inbox automation",
    defaultName: "automation",
    description:
      "Generate disposable addresses and read incoming mail. Best for test runners, signup bots, and automation tools.",
    scopes: ["inbox:read", "inbox:write"],
    icon: Inbox,
  },
  {
    id: "read-only",
    name: "Read-only monitor",
    defaultName: "monitor",
    description:
      "Read mail, addresses, rules, destinations, workers, and config without changing anything.",
    scopes: READ_SCOPES,
    icon: ShieldCheck,
  },
  {
    id: "routing",
    name: "Routing automation",
    defaultName: "routing",
    description:
      "Manage forwarding destinations, literal routing rules, and catch-all behaviour.",
    scopes: [
      "rules:read",
      "rules:write",
      "destinations:read",
      "destinations:write",
      "domains:read",
    ],
    icon: Route,
  },
  {
    id: "full",
    name: "Full access",
    defaultName: "full-access",
    description: "Every scope, including API key management. Only for trusted automation.",
    scopes: ["*"],
    icon: Zap,
  },
]

const METHOD_STYLES: Record<HttpMethod, string> = {
  GET: "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  POST: "bg-blue-500/10 text-blue-700 dark:text-blue-300",
  PUT: "bg-amber-500/10 text-amber-700 dark:text-amber-300",
  DELETE: "bg-destructive/10 text-destructive",
}

function CodeBlock({ code, label = "bash" }: { code: string; label?: string }) {
  return (
    <div className="overflow-hidden rounded-xl border border-border/70 bg-muted/35">
      <div className="flex items-center justify-between gap-2 border-b border-border/60 px-3 py-1.5">
        <span className="font-mono text-[10px] tracking-wide text-muted-foreground uppercase">
          {label}
        </span>
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          aria-label="Copy code"
          onClick={() => {
            void copyText(code)
              .then(() => toast.success("Copied to clipboard"))
              .catch(() => toast.error("Could not copy"))
          }}
        >
          <Copy />
        </Button>
      </div>
      <pre className="overflow-x-auto p-3.5 text-[11px] leading-relaxed">
        <code>{code}</code>
      </pre>
    </div>
  )
}

function ScopeBadges({ scopes }: { scopes: string[] }) {
  if (!scopes.length) return <span className="text-[10px] text-muted-foreground">None</span>
  if (scopes.includes("*")) {
    return (
      <Badge variant="secondary" className="text-[10px]">
        Full access
      </Badge>
    )
  }
  return (
    <div className="flex flex-wrap gap-1">
      {scopes.map((scope) => (
        <Badge key={scope} variant="outline" className="font-mono text-[10px]">
          {scope}
        </Badge>
      ))}
    </div>
  )
}

export function ApiDocsPage() {
  const queryClient = useQueryClient()
  const baseUrl = typeof window === "undefined" ? "https://mail.example.com" : window.location.origin

  const [createOpen, setCreateOpen] = React.useState(false)
  const [name, setName] = React.useState("")
  const [scopes, setScopes] = React.useState<string[]>([])
  const [templateId, setTemplateId] = React.useState<string | null>(null)
  const [formError, setFormError] = React.useState("")
  const [created, setCreated] = React.useState<CreatedApiKey | null>(null)
  const [revokeTarget, setRevokeTarget] = React.useState<ApiKey | null>(null)

  const keysQuery = useQuery({
    queryKey: queryKeys.apiKeys,
    queryFn: apiClient.apiKeys,
    staleTime: 60_000,
    retry: 1,
  })

  const createMutation = useMutation({
    mutationFn: apiClient.createApiKey,
    onSuccess: (data) => {
      setCreated(data)
      setFormError("")
      void queryClient.invalidateQueries({ queryKey: queryKeys.apiKeys })
    },
    onError: (error: Error) => setFormError(error.message),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiClient.deleteApiKey(id),
    onSuccess: async () => {
      toast.success("API key revoked")
      setRevokeTarget(null)
      await queryClient.invalidateQueries({ queryKey: queryKeys.apiKeys })
    },
    onError: (error: Error) => {
      toast.error("Could not revoke key", { description: error.message })
    },
  })

  const closeCreate = (open: boolean) => {
    setCreateOpen(open)
    if (!open) {
      setName("")
      setScopes([])
      setTemplateId(null)
      setFormError("")
      setCreated(null)
    }
  }

  const applyTemplate = (template: KeyTemplate) => {
    setTemplateId(template.id)
    setScopes(template.scopes)
    setName((current) => (current.trim() ? current : template.defaultName))
    setFormError("")
  }

  const toggleScope = (scope: string) => {
    setTemplateId(null)
    setScopes((current) => {
      if (current.includes("*")) {
        return ALL_SCOPES.filter((value) => value !== scope)
      }
      return current.includes(scope)
        ? current.filter((value) => value !== scope)
        : [...current, scope]
    })
    setFormError("")
  }

  const submitCreate = (event: React.FormEvent) => {
    event.preventDefault()
    if (!name.trim()) {
      setFormError("Give the key a name so you can identify it later.")
      return
    }
    if (!scopes.length) {
      setFormError("Select at least one scope.")
      return
    }
    createMutation.mutate({ name: name.trim(), scopes })
  }

  const keys = keysQuery.data?.apiKeys ?? []

  const authExample = `curl ${baseUrl}/api/destinations \\
  -H "Authorization: Bearer cfm_your_api_key"`

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Developers"
        title="REST API and keys"
        description="Automate the panel with scoped API keys. Every request is authorised with a bearer key and checked against the permissions you grant here."
        actions={
          <Button onClick={() => setCreateOpen(true)}>
            <Plus />
            Create API key
          </Button>
        }
      />

      <Tabs defaultValue="overview" className="gap-5">
        <TabsList className="h-10 w-full justify-start gap-1 overflow-x-auto rounded-xl bg-muted/60 p-1 sm:w-fit">
          <TabsTrigger value="overview" className="gap-1.5 px-3">
            <BookOpen />
            Overview
          </TabsTrigger>
          <TabsTrigger value="endpoints" className="gap-1.5 px-3">
            <Braces />
            Endpoints
          </TabsTrigger>
          <TabsTrigger value="keys" className="gap-1.5 px-3">
            <KeyRound />
            API keys
          </TabsTrigger>
          <TabsTrigger value="examples" className="gap-1.5 px-3">
            <Terminal />
            Examples
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-[1.1fr_0.9fr]">
            <div className="surface-card rounded-2xl p-5">
              <h2 className="text-sm font-semibold">Authentication</h2>
              <p className="mt-0.5 text-[11px] text-muted-foreground">
                Send the key as a bearer token. The <span className="font-mono">X-API-Key</span>{" "}
                header also works.
              </p>
              <div className="mt-4">
                <CodeBlock code={authExample} />
              </div>
              <div className="mt-4 rounded-xl border border-border/70 bg-muted/25 p-3 text-[11px] leading-relaxed text-muted-foreground">
                <p>
                  Base URL: <span className="font-mono text-foreground">{baseUrl}</span>
                </p>
                <p className="mt-1">
                  Responses are JSON. Errors return{" "}
                  <span className="font-mono">{`{ "error": "..." }`}</span> with a 4xx or 5xx
                  status.
                </p>
              </div>
            </div>

            <div className="surface-card rounded-2xl p-5">
              <div className="flex items-center gap-2">
                <div className="grid size-9 place-items-center rounded-xl bg-emerald-500/10 text-emerald-600 dark:text-emerald-400">
                  <ShieldCheck className="size-4" />
                </div>
                <div>
                  <h2 className="text-sm font-semibold">How keys are stored</h2>
                  <p className="text-[11px] text-muted-foreground">Hashed at rest</p>
                </div>
              </div>
              <ul className="mt-4 space-y-2.5 text-[11px] leading-relaxed text-muted-foreground">
                {[
                  "Only a SHA-256 hash is written to DATA_DIR/api-keys.json.",
                  "The plaintext key is shown once, right after creation.",
                  "Keys are scoped; read-only keys cannot mutate anything.",
                  "Revoking a key takes effect on the next request.",
                ].map((item) => (
                  <li key={item} className="flex items-start gap-2">
                    <Check className="mt-0.5 size-3.5 shrink-0 text-emerald-500" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          <div className="surface-card rounded-2xl p-5">
            <h2 className="text-sm font-semibold">Quick start</h2>
            <ol className="mt-3 space-y-3 text-[12px] leading-relaxed text-muted-foreground">
              <li className="flex gap-3">
                <span className="grid size-6 shrink-0 place-items-center rounded-full bg-primary/10 text-[10px] font-semibold text-primary">
                  1
                </span>
                <span>
                  Open <span className="font-medium text-foreground">API keys</span> and create a
                  key with the scopes you need.
                </span>
              </li>
              <li className="flex gap-3">
                <span className="grid size-6 shrink-0 place-items-center rounded-full bg-primary/10 text-[10px] font-semibold text-primary">
                  2
                </span>
                <span>Copy the key once and store it in your secret manager. It cannot be shown again.</span>
              </li>
              <li className="flex gap-3">
                <span className="grid size-6 shrink-0 place-items-center rounded-full bg-primary/10 text-[10px] font-semibold text-primary">
                  3
                </span>
                <span>
                  Call any endpoint with{" "}
                  <span className="font-mono">Authorization: Bearer &lt;key&gt;</span>. CORS is
                  enabled for browser clients.
                </span>
              </li>
            </ol>
          </div>

          <div className="flex items-start gap-2 rounded-2xl border border-border/70 bg-muted/25 p-4 text-[11px] text-muted-foreground">
            <CircleAlert className="mt-0.5 size-4 shrink-0" />
            <p>
              API keys bypass the login captcha by design. Keep them server-side, rotate them
              regularly, and prefer read-only scopes where possible.
            </p>
          </div>
        </TabsContent>

        <TabsContent value="endpoints" className="space-y-4">
          {ENDPOINT_GROUPS.map((group) => (
            <div key={group.name} className="surface-card overflow-hidden rounded-2xl">
              <div className="border-b border-border/60 px-5 py-4">
                <h2 className="text-sm font-semibold">{group.name}</h2>
                <p className="mt-0.5 text-[11px] text-muted-foreground">{group.description}</p>
              </div>
              <div className="divide-y divide-border/60">
                {group.endpoints.map((endpoint) => (
                  <div key={`${endpoint.method}-${endpoint.path}`} className="px-4 py-3.5 sm:px-5">
                    <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                      <div className="min-w-0 flex-1">
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={cn(
                              "rounded-md px-1.5 py-0.5 font-mono text-[10px] font-semibold",
                              METHOD_STYLES[endpoint.method]
                            )}
                          >
                            {endpoint.method}
                          </span>
                          <code className="text-[12px] font-medium break-all">
                            {endpoint.path}
                          </code>
                        </div>
                        <p className="mt-1.5 text-[11px] leading-relaxed text-muted-foreground">
                          {endpoint.description}
                        </p>
                        {endpoint.query && (
                          <p className="mt-1 text-[10px] text-muted-foreground">
                            Query: <span className="font-mono">{endpoint.query}</span>
                          </p>
                        )}
                      </div>
                      <Badge variant="outline" className="shrink-0 font-mono text-[10px]">
                        {endpoint.scope}
                      </Badge>
                    </div>
                    {endpoint.body && (
                      <details className="mt-2.5">
                        <summary className="cursor-pointer text-[10px] font-medium text-muted-foreground hover:text-foreground">
                          Request body
                        </summary>
                        <div className="mt-2">
                          <CodeBlock code={endpoint.body} label="json" />
                        </div>
                      </details>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}

          <div className="surface-card rounded-2xl p-5">
            <h2 className="text-sm font-semibold">Unauthenticated</h2>
            <p className="mt-1 text-[11px] text-muted-foreground">
              <span className="font-mono text-foreground">GET /healthz</span> returns{" "}
              <span className="font-mono">{`{ "ok": true }`}</span>. Use it for uptime checks.
            </p>
          </div>
        </TabsContent>

        <TabsContent value="keys" className="space-y-4">
          <div className="surface-card overflow-hidden rounded-2xl">
            <div className="flex flex-col gap-3 border-b border-border/60 px-5 py-4 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-sm font-semibold">Your API keys</h2>
                <p className="mt-0.5 text-[11px] text-muted-foreground">
                  Keys inherit only the scopes selected at creation.
                </p>
              </div>
              <Button size="sm" onClick={() => setCreateOpen(true)}>
                <Plus />
                New key
              </Button>
            </div>

            {keysQuery.isLoading ? (
              <div className="space-y-2 p-4">
                {Array.from({ length: 3 }).map((_, index) => (
                  <Skeleton key={index} className="h-16 rounded-xl" />
                ))}
              </div>
            ) : keysQuery.error ? (
              <div className="p-4">
                <ErrorState
                  title="Could not load API keys"
                  message={keysQuery.error.message}
                  onRetry={() => void keysQuery.refetch()}
                />
              </div>
            ) : keys.length ? (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="pl-5">Name</TableHead>
                    <TableHead>Key</TableHead>
                    <TableHead className="hidden md:table-cell">Scopes</TableHead>
                    <TableHead className="hidden lg:table-cell">Created</TableHead>
                    <TableHead className="hidden lg:table-cell">Last used</TableHead>
                    <TableHead className="pr-5 text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {keys.map((key) => (
                    <TableRow key={key.id}>
                      <TableCell className="pl-5 font-medium">{key.name}</TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground">
                        {key.prefix}…
                      </TableCell>
                      <TableCell className="hidden max-w-72 whitespace-normal md:table-cell">
                        <ScopeBadges scopes={key.scopes} />
                      </TableCell>
                      <TableCell className="hidden text-[11px] text-muted-foreground lg:table-cell">
                        {formatDateTime(key.createdAt)}
                      </TableCell>
                      <TableCell className="hidden text-[11px] text-muted-foreground lg:table-cell">
                        {key.lastUsedAt ? formatDateTime(key.lastUsedAt) : "Never"}
                      </TableCell>
                      <TableCell className="pr-5 text-right">
                        <Button
                          variant="ghost"
                          size="icon-sm"
                          className="text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
                          onClick={() => setRevokeTarget(key)}
                          aria-label={`Revoke ${key.name}`}
                        >
                          <Trash2 />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            ) : (
              <EmptyState
                icon={KeyRound}
                title="No API keys yet"
                description="Create a scoped key to call the REST API from scripts, CI, or another service."
                action={
                  <Button size="sm" onClick={() => setCreateOpen(true)}>
                    <Plus />
                    Create API key
                  </Button>
                }
              />
            )}
          </div>

          <div className="surface-card rounded-2xl p-5">
            <h2 className="text-sm font-semibold">Available scopes</h2>
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              {SCOPE_GROUPS.map((group) => (
                <div key={group.label} className="rounded-xl border border-border/70 bg-muted/20 p-3">
                  <p className="text-[11px] font-semibold">{group.label}</p>
                  <ul className="mt-2 space-y-1.5">
                    {group.scopes.map((scope) => (
                      <li key={scope.value} className="flex items-start justify-between gap-3">
                        <span className="font-mono text-[10px] text-foreground">{scope.value}</span>
                        <span className="text-right text-[10px] text-muted-foreground">
                          {scope.description}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              ))}
            </div>
            <p className="mt-3 flex items-start gap-2 text-[10px] leading-relaxed text-muted-foreground">
              <LockKeyhole className="mt-0.5 size-3.5 shrink-0" />
              Full access (<span className="font-mono">*</span>) includes key management. Grant it
              only to trusted automation.
            </p>
          </div>

          <div className="surface-card rounded-2xl p-5">
            <h2 className="text-sm font-semibold">Key templates</h2>
            <p className="mt-0.5 text-[11px] text-muted-foreground">
              Presets for common integrations. Pick one here, then fine-tune the scopes before
              creating the key.
            </p>
            <div className="mt-3 grid gap-3 sm:grid-cols-2">
              {KEY_TEMPLATES.map((template) => {
                const Icon = template.icon
                return (
                  <div
                    key={template.id}
                    className="rounded-xl border border-border/70 bg-muted/20 p-3"
                  >
                    <div className="flex items-center gap-2">
                      <Icon className="size-3.5 text-primary" />
                      <span className="text-[11px] font-medium">{template.name}</span>
                      <Badge variant="outline" className="ml-auto text-[10px]">
                        {template.scopes.includes("*") ? "all" : `${template.scopes.length} scopes`}
                      </Badge>
                    </div>
                    <p className="mt-1.5 text-[10px] leading-relaxed text-muted-foreground">
                      {template.description}
                    </p>
                    <p className="mt-1.5 font-mono text-[9.5px] text-muted-foreground">
                      {template.scopes.join(" + ")}
                    </p>
                    <Button
                      variant="outline"
                      size="sm"
                      className="mt-2 h-7 text-[10px]"
                      onClick={() => {
                        applyTemplate(template)
                        setCreateOpen(true)
                      }}
                    >
                      Use template
                    </Button>
                  </div>
                )
              })}
            </div>
          </div>
        </TabsContent>

        <TabsContent value="examples" className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-2">
            <div className="surface-card rounded-2xl p-5">
              <h2 className="text-sm font-semibold">List destinations</h2>
              <p className="mt-0.5 text-[11px] text-muted-foreground">cURL</p>
              <div className="mt-3">
                <CodeBlock
                  code={`curl ${baseUrl}/api/destinations \\
  -H "Authorization: Bearer cfm_your_api_key"`}
                />
              </div>
            </div>

            <div className="surface-card rounded-2xl p-5">
              <h2 className="text-sm font-semibold">Create a routing rule</h2>
              <p className="mt-0.5 text-[11px] text-muted-foreground">JavaScript fetch</p>
              <div className="mt-3">
                <CodeBlock
                  label="javascript"
                  code={`const res = await fetch("${baseUrl}/api/rules", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    Authorization: "Bearer cfm_your_api_key",
  },
  body: JSON.stringify({
    zoneId: "zone_id",
    customEmail: "hello@example.com",
    type: "worker",
    destinationId: "inbox-worker",
  }),
});
const rule = await res.json();`}
                />
              </div>
            </div>

            <div className="surface-card rounded-2xl p-5">
              <h2 className="text-sm font-semibold">Read the inbox</h2>
              <p className="mt-0.5 text-[11px] text-muted-foreground">Python requests</p>
              <div className="mt-3">
                <CodeBlock
                  label="python"
                  code={`import requests

headers = {"Authorization": "Bearer cfm_your_api_key"}
res = requests.get(
    "${baseUrl}/api/inbox",
    params={"limit": 20, "offset": 0},
    headers=headers,
    timeout=30,
)
res.raise_for_status()
messages = res.json()`}
                />
              </div>
            </div>

            <div className="surface-card rounded-2xl p-5">
              <h2 className="text-sm font-semibold">Revoke a key</h2>
              <p className="mt-0.5 text-[11px] text-muted-foreground">cURL</p>
              <div className="mt-3">
                <CodeBlock
                  code={`curl -X DELETE ${baseUrl}/api/keys/key_id \\
  -H "Authorization: Bearer cfm_your_api_key"`}
                />
              </div>
            </div>

            <div className="surface-card rounded-2xl p-5 lg:col-span-2">
              <h2 className="text-sm font-semibold">Automation: address + inbox</h2>
              <p className="mt-0.5 text-[11px] text-muted-foreground">
                Uses the <span className="font-medium text-foreground">Address + inbox automation</span>{" "}
                template. It needs only <span className="font-mono">inbox:read</span> and{" "}
                <span className="font-mono">inbox:write</span>.
              </p>
              <div className="mt-3">
                <CodeBlock
                  label="javascript"
                  code={`const baseUrl = "${baseUrl}";
const headers = {
  Authorization: "Bearer cfm_your_api_key",
  "Content-Type": "application/json",
};

const address = \`test-\${Date.now()}@your-domain.com\`;

// Register the disposable address so it shows up in the panel.
await fetch(\`${baseUrl}/api/addresses\`, {
  method: "POST",
  headers,
  body: JSON.stringify({ address }),
});

// Poll this mailbox for incoming messages.
const res = await fetch(
  \`${baseUrl}/api/inbox?recipient=\${encodeURIComponent(address)}&limit=10\`,
  { headers },
);
const messages = await res.json();`}
                />
              </div>
            </div>
          </div>

          <div className="surface-card rounded-2xl p-5">
            <h2 className="text-sm font-semibold">Rate limits and errors</h2>
            <ul className="mt-3 space-y-2 text-[11px] leading-relaxed text-muted-foreground">
              <li>
                <span className="font-mono text-foreground">401</span> means the key is missing,
                invalid, or revoked.
              </li>
              <li>
                <span className="font-mono text-foreground">403</span> means the key lacks the
                required scope for that method and path.
              </li>
              <li>
                Login attempts are limited to five per minute per IP, with escalating lockouts.
                API key calls are not subject to the login limiter.
              </li>
            </ul>
          </div>
        </TabsContent>
      </Tabs>

      <Dialog open={createOpen} onOpenChange={closeCreate}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{created ? "Key created" : "Create an API key"}</DialogTitle>
            <DialogDescription>
              {created
                ? "Copy the key now. Only its hash is stored, so it cannot be shown again."
                : "Choose a name and the exact scopes this key may use."}
            </DialogDescription>
          </DialogHeader>

          {created ? (
            <div className="space-y-4">
              <CodeBlock code={created.key} label="api key" />
              <div className="flex items-start gap-2 rounded-xl border border-amber-500/25 bg-amber-500/8 p-3 text-[11px] leading-relaxed text-amber-700 dark:text-amber-300">
                <CircleAlert className="mt-0.5 size-3.5 shrink-0" />
                <span>
                  Store this key in your secret manager now. If you lose it, revoke it and create a
                  new one.
                </span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <ScopeBadges scopes={created.apiKey.scopes} />
                <Button onClick={() => closeCreate(false)}>
                  <Check />
                  Done
                </Button>
              </div>
            </div>
          ) : (
            <form onSubmit={submitCreate} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="key-name">Key name</Label>
                <Input
                  id="key-name"
                  value={name}
                  onChange={(event) => {
                    setName(event.target.value)
                    setFormError("")
                  }}
                  placeholder="ci-deploy"
                  autoFocus
                />
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <Label>Template</Label>
                  <span className="text-[10px] text-muted-foreground">
                    {templateId ? "Preset applied" : "Custom scopes"}
                  </span>
                </div>
                <div className="grid gap-2 sm:grid-cols-2">
                  {KEY_TEMPLATES.map((template) => {
                    const Icon = template.icon
                    const selected = templateId === template.id
                    return (
                      <button
                        key={template.id}
                        type="button"
                        onClick={() => applyTemplate(template)}
                        aria-pressed={selected}
                        className={cn(
                          "rounded-xl border p-2.5 text-left transition-colors",
                          selected
                            ? "border-primary/40 bg-primary/8"
                            : "border-border/70 hover:bg-muted/40"
                        )}
                      >
                        <div className="flex items-center gap-1.5">
                          <Icon
                            className={cn(
                              "size-3.5",
                              selected ? "text-primary" : "text-muted-foreground"
                            )}
                          />
                          <span className="text-[11px] font-medium">{template.name}</span>
                          {selected && <Check className="ml-auto size-3.5 text-primary" />}
                        </div>
                        <p className="mt-1 text-[10px] leading-relaxed text-muted-foreground">
                          {template.description}
                        </p>
                        <p className="mt-1.5 font-mono text-[9.5px] text-muted-foreground">
                          {template.scopes.includes("*")
                            ? "*"
                            : template.scopes.join(" + ")}
                        </p>
                      </button>
                    )
                  })}
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <Label>Scopes</Label>
                  <div className="flex gap-1">
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="h-7 px-2 text-[10px]"
                      onClick={() => {
                        setScopes(READ_SCOPES)
                        setTemplateId("read-only")
                        setFormError("")
                      }}
                    >
                      Read only
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="h-7 px-2 text-[10px]"
                      onClick={() => {
                        setScopes(["*"])
                        setTemplateId("full")
                        setFormError("")
                      }}
                    >
                      Full access
                    </Button>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="h-7 px-2 text-[10px]"
                      onClick={() => {
                        setScopes([])
                        setTemplateId(null)
                        setFormError("")
                      }}
                    >
                      Clear
                    </Button>
                  </div>
                </div>

                <div className="space-y-3 rounded-xl border border-border/70 bg-muted/20 p-3">
                  {SCOPE_GROUPS.map((group) => (
                    <div key={group.label}>
                      <p className="text-[10px] font-semibold tracking-[0.12em] text-muted-foreground uppercase">
                        {group.label}
                      </p>
                      <div className="mt-1.5 space-y-1.5">
                        {group.scopes.map((scope) => (
                          <label
                            key={scope.value}
                            className="flex cursor-pointer items-start gap-2.5 rounded-lg px-1 py-1 text-[11px] hover:bg-muted/50"
                          >
                            <input
                              type="checkbox"
                              className="mt-0.5 size-3.5 shrink-0 accent-primary"
                              checked={scopes.includes(scope.value) || scopes.includes("*")}
                              onChange={() => toggleScope(scope.value)}
                            />
                            <span className="min-w-0 flex-1">
                              <span className="block font-mono text-[10.5px]">{scope.value}</span>
                              <span className="block text-[10px] text-muted-foreground">
                                {scope.description}
                              </span>
                            </span>
                          </label>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>

                <p className="flex items-start gap-2 text-[10px] leading-relaxed text-muted-foreground">
                  <ShieldCheck className="mt-0.5 size-3.5 shrink-0" />
                  Selecting a scope makes every matching endpoint available with this one key.
                </p>
              </div>

              {formError && (
                <p role="alert" className="text-xs font-medium text-destructive">
                  {formError}
                </p>
              )}

              <div className="flex justify-end gap-2">
                <Button type="button" variant="outline" onClick={() => closeCreate(false)}>
                  Cancel
                </Button>
                <Button type="submit" disabled={createMutation.isPending}>
                  {createMutation.isPending ? <Loader2 className="animate-spin" /> : <KeyRound />}
                  {createMutation.isPending ? "Creating…" : "Create key"}
                </Button>
              </div>
            </form>
          )}
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={Boolean(revokeTarget)}
        onOpenChange={(open) => !open && setRevokeTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke this API key?</AlertDialogTitle>
            <AlertDialogDescription>
              {revokeTarget
                ? `${revokeTarget.name} (${revokeTarget.prefix}…) will stop working immediately. This cannot be undone.`
                : ""}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => revokeTarget && deleteMutation.mutate(revokeTarget.id)}
              disabled={deleteMutation.isPending}
              className="bg-destructive text-white hover:bg-destructive/90"
            >
              {deleteMutation.isPending ? <Loader2 className="animate-spin" /> : <Trash2 />}
              Revoke
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
