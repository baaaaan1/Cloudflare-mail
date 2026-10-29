import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  BadgeCheck,
  CircleAlert,
  Clock,
  ExternalLink,
  Loader2,
  Mail,
  Plus,
  RefreshCw,
  Send,
  ShieldCheck,
  Trash2,
} from "lucide-react"
import { motion, useReducedMotion } from "motion/react"
import { toast } from "sonner"

import { EmptyState } from "@/components/empty-state"
import { ErrorState } from "@/components/error-state"
import { PageHeader } from "@/components/page-header"
import { StatCard } from "@/components/stat-card"
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
import { apiClient } from "@/lib/api"
import { formatDateTime, normalizeAddress } from "@/lib/format"
import { queryKeys } from "@/lib/query-keys"
import type { Destination } from "@/lib/types"
import { cn } from "cn"

export function DestinationsPage() {
  const queryClient = useQueryClient()
  const prefersReducedMotion = useReducedMotion()

  const [addOpen, setAddOpen] = React.useState(false)
  const [value, setValue] = React.useState("")
  const [formError, setFormError] = React.useState("")
  const [deleteTarget, setDeleteTarget] = React.useState<Destination | null>(null)

  const destinationsQuery = useQuery({
    queryKey: queryKeys.destinations,
    queryFn: apiClient.destinations,
    staleTime: 5 * 60_000,
    retry: 1,
  })

  const destinations = destinationsQuery.data ?? []
  const verifiedCount = destinations.filter((item) => Boolean(item.verified)).length
  const pendingCount = destinations.length - verifiedCount

  const createMutation = useMutation({
    mutationFn: (email: string) => apiClient.createDestination(email),
    onSuccess: async (destination) => {
      toast.success("Destination added", {
        description: `${destination.email} will appear as verified after you confirm the Cloudflare email.`,
      })
      setAddOpen(false)
      setValue("")
      setFormError("")
      await queryClient.invalidateQueries({ queryKey: queryKeys.destinations })
    },
    onError: (error: Error) => setFormError(error.message),
  })

  const deleteMutation = useMutation({
    mutationFn: (destination: Destination) => apiClient.deleteDestination(destination.id),
    onSuccess: async () => {
      toast.success("Destination deleted")
      setDeleteTarget(null)
      await queryClient.invalidateQueries({ queryKey: queryKeys.destinations })
    },
    onError: (error: Error) => {
      toast.error("Could not delete destination", { description: error.message })
    },
  })

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    const email = normalizeAddress(value)
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      setFormError("Enter a valid email address.")
      return
    }
    setFormError("")
    createMutation.mutate(email)
  }

  return (
    <div className="space-y-6">
      <PageHeader
        eyebrow="Delivery"
        title="Verified destinations"
        description="Forwarding targets for your Cloudflare account. Cloudflare emails the address to verify it before rules can use it."
        actions={
          <>
            <Button
              variant="outline"
              onClick={() => void destinationsQuery.refetch()}
              disabled={destinationsQuery.isFetching}
            >
              <RefreshCw className={cn(destinationsQuery.isFetching && "animate-spin")} />
              Refresh
            </Button>
            <Button onClick={() => setAddOpen(true)}>
              <Plus />
              Add destination
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
        <StatCard label="Destinations" value={destinations.length} icon={Send} hint="Account-wide" />
        <StatCard label="Verified" value={verifiedCount} icon={BadgeCheck} accent="blue" hint="Ready to forward" />
        <StatCard label="Pending" value={pendingCount} icon={Clock} accent="amber" hint="Awaiting confirmation" />
        <StatCard label="Security" value={verifiedCount} icon={ShieldCheck} accent="violet" hint="Verified targets only" />
      </div>

      <div className="surface-card overflow-hidden rounded-2xl">
        <div className="border-b border-border/60 px-4 py-3.5">
          <h2 className="text-sm font-semibold">Account destinations</h2>
          <p className="mt-0.5 text-[11px] text-muted-foreground">
            Forwarding rules can only target verified addresses.
          </p>
        </div>

        {destinationsQuery.isLoading ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 4 }).map((_, index) => (
              <Skeleton key={index} className="h-16 rounded-xl" />
            ))}
          </div>
        ) : destinationsQuery.error ? (
          <div className="p-4">
            <ErrorState
              title="Could not load destinations"
              message={destinationsQuery.error.message}
              onRetry={() => void destinationsQuery.refetch()}
            />
          </div>
        ) : destinations.length ? (
          <div className="divide-y divide-border/60">
            {destinations.map((destination, index) => {
              const verified = Boolean(destination.verified)
              return (
                <motion.div
                  key={destination.id}
                  initial={prefersReducedMotion ? false : { opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{
                    duration: 0.3,
                    delay: Math.min(index, 10) * 0.03,
                    ease: [0.22, 1, 0.36, 1],
                  }}
                  className="group flex flex-col gap-3 px-3 py-3 transition-colors hover:bg-muted/30 sm:flex-row sm:items-center sm:px-4"
                >
                  <div
                    className={cn(
                      "grid size-9 shrink-0 place-items-center rounded-xl",
                      verified
                        ? "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400"
                        : "bg-amber-500/10 text-amber-600 dark:text-amber-400"
                    )}
                  >
                    {verified ? <BadgeCheck className="size-4" /> : <Clock className="size-4" />}
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-[13px] font-medium">
                      {destination.email}
                    </p>
                    <div className="mt-1 flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
                      <Badge
                        variant="secondary"
                        className={cn(
                          "text-[10px]",
                          verified
                            ? "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                            : "bg-amber-500/10 text-amber-700 dark:text-amber-300"
                        )}
                      >
                        {verified ? "Verified" : "Pending verification"}
                      </Badge>
                      {destination.created && (
                        <span>Added {formatDateTime(destination.created)}</span>
                      )}
                    </div>
                  </div>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    className="self-end text-muted-foreground hover:bg-destructive/10 hover:text-destructive sm:self-auto"
                    onClick={() => setDeleteTarget(destination)}
                    aria-label={`Delete ${destination.email}`}
                  >
                    <Trash2 />
                  </Button>
                </motion.div>
              )
            })}
          </div>
        ) : (
          <EmptyState
            icon={Send}
            title="No destinations yet"
            description="Add a forwarding address. Cloudflare will email it a verification link before it can receive mail."
            action={
              <Button size="sm" onClick={() => setAddOpen(true)}>
                <Plus />
                Add destination
              </Button>
            }
          />
        )}
      </div>

      <div className="flex items-start gap-2 rounded-2xl border border-border/70 bg-muted/25 p-4 text-[11px] text-muted-foreground">
        <CircleAlert className="mt-0.5 size-4 shrink-0" />
        <p>
          Destinations are managed at the Cloudflare account level and are shared by every zone.
          You can also manage them in the{" "}
          <a
            href="https://dash.cloudflare.com/?to=/:account/email/routing/overview"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-0.5 font-medium text-foreground underline underline-offset-2"
          >
            Cloudflare dashboard <ExternalLink className="size-3" />
          </a>
          .
        </p>
      </div>

      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Add a destination</DialogTitle>
            <DialogDescription>
              Cloudflare sends a verification email to this address. Forwarding works once it is
              confirmed.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={submit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="destination-email">Forwarding email</Label>
              <div className="relative">
                <Mail className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="destination-email"
                  value={value}
                  onChange={(event) => {
                    setValue(event.target.value)
                    setFormError("")
                  }}
                  placeholder="you@example.com"
                  className="pl-9 font-mono text-[13px]"
                  autoFocus
                />
              </div>
              {formError && (
                <p role="alert" className="text-xs font-medium text-destructive">
                  {formError}
                </p>
              )}
            </div>
            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => setAddOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={createMutation.isPending}>
                {createMutation.isPending ? <Loader2 className="animate-spin" /> : <Plus />}
                {createMutation.isPending ? "Adding…" : "Add destination"}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>

      <AlertDialog open={Boolean(deleteTarget)} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete destination?</AlertDialogTitle>
            <AlertDialogDescription>
              {deleteTarget
                ? `${deleteTarget.email} will stop receiving forwarded mail. Rules that target it may fail until they are updated.`
                : ""}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteTarget && deleteMutation.mutate(deleteTarget)}
              disabled={deleteMutation.isPending}
              className="bg-destructive text-white hover:bg-destructive/90"
            >
              {deleteMutation.isPending ? <Loader2 className="animate-spin" /> : <Trash2 />}
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
