import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  Check,
  Code2,
  Copy,
  Inbox,
  Loader2,
  Mail,
  Trash2,
  Type,
  X,
} from "lucide-react"
import { motion } from "motion/react"
import { toast } from "sonner"

import { ErrorState } from "@/components/error-state"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
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
import { Skeleton } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { apiClient } from "@/lib/api"
import { plainTextBody, wrapEmailHtml } from "@/lib/email"
import {
  avatarTone,
  copyText,
  formatFullDate,
  getInitials,
  parseSender,
} from "@/lib/format"
import { queryKeys } from "@/lib/query-keys"
import { cn } from "cn"

type EmailReaderProps = {
  messageId: number | null
  onClose: () => void
  onDeleted?: () => void
}

export function EmailReader({ messageId, onClose, onDeleted }: EmailReaderProps) {
  const queryClient = useQueryClient()
  const [tab, setTab] = React.useState("html")
  const [confirmOpen, setConfirmOpen] = React.useState(false)

  const emailQuery = useQuery({
    queryKey: queryKeys.email(messageId),
    queryFn: () => apiClient.email(messageId as number),
    enabled: messageId !== null,
    staleTime: 60_000,
    retry: 1,
  })

  const message = emailQuery.data

  React.useEffect(() => {
    if (!message) return
    setTab(message.html_body?.trim() ? "html" : "text")
  }, [message])

  const deleteMutation = useMutation({
    mutationFn: (id: number) => apiClient.deleteEmail(id),
    onSuccess: async () => {
      toast.success("Message deleted")
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["inbox"] }),
        queryClient.invalidateQueries({ queryKey: queryKeys.inboxSummary }),
      ])
      setConfirmOpen(false)
      onDeleted?.()
      onClose()
    },
    onError: (error: Error) => {
      toast.error("Could not delete message", { description: error.message })
    },
  })

  const sender = parseSender(message?.sender)

  const copy = (value: string, label: string) => {
    void copyText(value)
      .then(() => toast.success(`${label} copied`))
      .catch(() => toast.error("Could not copy"))
  }

  if (messageId === null) {
    return (
      <div className="flex h-full flex-col items-center justify-center px-8 text-center">
        <div className="relative mb-5 grid size-16 place-items-center rounded-2xl border border-border/70 bg-muted/40">
          <div className="absolute inset-0 rounded-2xl bg-primary/5 blur-2xl" />
          <Inbox className="relative size-7 text-muted-foreground" strokeWidth={1.5} />
        </div>
        <h3 className="text-base font-semibold">Select a message</h3>
        <p className="mt-1.5 max-w-xs text-sm leading-relaxed text-muted-foreground">
          Pick a conversation from the list to read it here. Press{" "}
          <kbd className="rounded border border-border bg-muted/60 px-1.5 py-0.5 font-mono text-[10px]">J</kbd>{" "}
          or{" "}
          <kbd className="rounded border border-border bg-muted/60 px-1.5 py-0.5 font-mono text-[10px]">K</kbd>{" "}
          to move between messages.
        </p>
      </div>
    )
  }

  if (emailQuery.isLoading) {
    return (
      <div className="space-y-4 p-5">
        <Skeleton className="h-6 w-2/3" />
        <div className="flex items-center gap-3">
          <Skeleton className="size-10 rounded-full" />
          <div className="space-y-2">
            <Skeleton className="h-3.5 w-40" />
            <Skeleton className="h-3 w-56" />
          </div>
        </div>
        <Skeleton className="h-40 w-full rounded-xl" />
      </div>
    )
  }

  if (emailQuery.error) {
    return (
      <div className="p-5">
        <ErrorState
          title="Could not load this message"
          message={emailQuery.error.message}
          onRetry={() => void emailQuery.refetch()}
        />
      </div>
    )
  }

  if (!message) return null

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="border-b border-border/60 p-4 sm:p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <Badge variant="secondary" className="bg-primary/8 text-primary">
                <Mail className="size-3" />
                Inbox
              </Badge>
              <span className="text-[11px] text-muted-foreground">
                {formatFullDate(message.created_at)}
              </span>
            </div>
            <h2 className="text-lg font-semibold tracking-tight text-balance break-words sm:text-xl">
              {message.subject?.trim() || "(No subject)"}
            </h2>
          </div>
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={onClose}
            aria-label="Close message"
            className="shrink-0"
          >
            <X />
          </Button>
        </div>

        <div className="mt-4 flex items-center gap-3">
          <div
            className={cn(
              "grid size-10 shrink-0 place-items-center rounded-full text-xs font-semibold",
              avatarTone(sender.email || sender.label)
            )}
          >
            {getInitials(sender.label)}
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-baseline gap-x-2">
              <span className="truncate text-sm font-medium">{sender.label}</span>
              <span className="truncate font-mono text-[11px] text-muted-foreground">
                {sender.email || "unknown sender"}
              </span>
            </div>
            <p className="mt-0.5 truncate text-[11px] text-muted-foreground">
              to <span className="font-mono">{message.recipient || "unknown recipient"}</span>
            </p>
          </div>
          <div className="flex shrink-0 items-center gap-1">
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={() => copy(message.sender || "", "Sender")}
              aria-label="Copy sender"
              title="Copy sender"
            >
              <Copy />
            </Button>
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={() => setConfirmOpen(true)}
              aria-label="Delete message"
              title="Delete message"
              className="text-muted-foreground hover:bg-destructive/10 hover:text-destructive"
            >
              <Trash2 />
            </Button>
          </div>
        </div>
      </div>

      <Tabs value={tab} onValueChange={setTab} className="min-h-0 flex-1 gap-0">
        <div className="flex items-center justify-between border-b border-border/60 px-4 py-2 sm:px-5">
          <TabsList>
            <TabsTrigger value="html">
              <Code2 />
              HTML
            </TabsTrigger>
            <TabsTrigger value="text">
              <Type />
              Text
            </TabsTrigger>
          </TabsList>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => copy(`${message.subject || ""}\n\n${plainTextBody(message.text_body)}`, "Message")}
          >
            <Copy />
            <span className="hidden sm:inline">Copy</span>
          </Button>
        </div>

        <TabsContent value="html" className="min-h-0 flex-1 overflow-hidden">
          {message.html_body?.trim() ? (
            <motion.iframe
              key={message.id}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.35 }}
              title="Email content"
              className="email-frame"
              sandbox="allow-same-origin allow-popups allow-popups-to-escape-sandbox"
              referrerPolicy="no-referrer"
              srcDoc={wrapEmailHtml(message.html_body)}
            />
          ) : (
            <div className="flex h-full flex-col items-center justify-center gap-2 p-6 text-center">
              <Mail className="size-6 text-muted-foreground" />
              <p className="text-sm font-medium">No HTML content</p>
              <p className="text-xs text-muted-foreground">
                Switch to the Text tab to read this message.
              </p>
            </div>
          )}
        </TabsContent>

        <TabsContent value="text" className="min-h-0 flex-1 overflow-hidden">
          <pre className="h-full overflow-auto p-5 font-sans text-[13px] leading-relaxed whitespace-pre-wrap break-words text-foreground/90 scrollbar-thin">
            {plainTextBody(message.text_body)}
          </pre>
        </TabsContent>
      </Tabs>

      <div className="flex items-center justify-between border-t border-border/60 px-4 py-2.5 text-[10px] text-muted-foreground sm:px-5">
        <span className="inline-flex items-center gap-1.5">
          <Check className="size-3 text-emerald-500" />
          Delivered to your D1 inbox
        </span>
        <span className="font-mono">#{message.id}</span>
      </div>

      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete this message?</AlertDialogTitle>
            <AlertDialogDescription>
              This removes “{message.subject?.trim() || "(No subject)"}” from your D1 inbox. This
              action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteMutation.isPending}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteMutation.mutate(message.id)}
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
