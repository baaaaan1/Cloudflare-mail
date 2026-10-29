import * as React from "react"
import { AnimatePresence, motion, useReducedMotion } from "motion/react"
import {
  ArrowRight,
  AtSign,
  Check,
  Loader2,
  Settings2,
  Sparkles,
  Wand2,
} from "lucide-react"

import { useCreateAddressDialog } from "@/components/create-address-context"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useCreateAddress } from "@/hooks/use-create-address"
import { useWorkspace } from "@/hooks/use-workspace"
import { NAME_STYLE_LABELS, createRandomLocalPart, validateLocalPart } from "@/lib/random"
import { navigate } from "@/lib/router"
import { STORAGE_KEYS } from "@/lib/query-keys"
import type { NameStyle } from "@/lib/types"
import { cn } from "cn"

function readNameStyle(): NameStyle {
  if (typeof window === "undefined") return "us"
  return localStorage.getItem(STORAGE_KEYS.nameStyle) === "id" ? "id" : "us"
}

export function CreateAddressDialog() {
  const { isOpen, setIsOpen } = useCreateAddressDialog()
  const { domains, workers, domainsLoading, domainsError } = useWorkspace()
  const prefersReducedMotion = useReducedMotion()

  const [localPart, setLocalPart] = React.useState("")
  const [domainId, setDomainId] = React.useState("")
  const [style, setStyle] = React.useState<NameStyle>(readNameStyle)
  const [error, setError] = React.useState("")

  const { createAddress, isCreating, reset } = useCreateAddress({
    onCreated: () => {
      setIsOpen(false)
      setLocalPart("")
      setError("")
    },
  })

  React.useEffect(() => {
    if (!isOpen) return
    reset()
    if (!domainId && domains.length) {
      setDomainId(domains[0].id)
    }
  }, [domains, domainId, isOpen, reset])

  const selectedDomain = domains.find((domain) => domain.id === domainId) ?? null
  const preview = `${localPart.trim() || "your.name"}@${selectedDomain?.name || "your-domain.com"}`
  const worker =
    workers.find((item) => /inbox/i.test(item.name || "")) ?? workers[0] ?? null

  const handleRandom = () => {
    setLocalPart(createRandomLocalPart(style))
    setError("")
    if (domains.length > 1) {
      const randomDomain = domains[Math.floor(Math.random() * domains.length)]
      if (randomDomain) setDomainId(randomDomain.id)
    }
  }

  const handleStyleChange = (value: string | null) => {
    const nextStyle = value === "id" ? "id" : "us"
    setStyle(nextStyle)
    localStorage.setItem(STORAGE_KEYS.nameStyle, nextStyle)
  }

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault()
    const validationError = validateLocalPart(localPart)
    if (validationError) {
      setError(validationError)
      return
    }
    if (!selectedDomain) {
      setError(
        domainsError
          ? "Domains could not be loaded. Check your Cloudflare credentials."
          : "Choose a domain for this address."
      )
      return
    }

    setError("")
    try {
      await createAddress({ localPart, domain: selectedDomain, style })
    } catch (creationError) {
      setError(
        creationError instanceof Error
          ? creationError.message
          : "Could not create this address."
      )
    }
  }

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogContent className="max-w-[calc(100%-1.5rem)] gap-0 overflow-hidden p-0 sm:max-w-lg">
        <div className="relative overflow-hidden border-b border-border/70 bg-muted/35 px-5 pt-5 pb-4">
          <div className="pointer-events-none absolute -top-16 -right-10 size-40 rounded-full bg-primary/15 blur-3xl" />
          <div className="relative flex items-start gap-3">
            <div className="grid size-10 place-items-center rounded-xl bg-primary/10 text-primary">
              <Sparkles className="size-5" />
            </div>
            <div className="min-w-0">
              <DialogTitle className="text-lg">Create an address</DialogTitle>
              <DialogDescription className="mt-1 text-[13px]">
                Spin up a disposable mailbox in seconds. Mail is delivered to your
                Cloudflare inbox worker.
              </DialogDescription>
            </div>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5 p-5">
          <div className="space-y-2">
            <Label htmlFor="create-local-part">Address name</Label>
            <div className="flex gap-2">
              <div className="relative min-w-0 flex-1">
                <AtSign className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  id="create-local-part"
                  value={localPart}
                  onChange={(event) => {
                    setLocalPart(event.target.value)
                    setError("")
                  }}
                  placeholder="hello.world"
                  className="pl-9 font-mono text-[13px]"
                  autoComplete="off"
                  spellCheck={false}
                  autoFocus
                  aria-invalid={Boolean(error)}
                />
              </div>
              <Button
                type="button"
                variant="outline"
                size="icon"
                onClick={handleRandom}
                title="Generate a random name"
                aria-label="Generate a random name"
              >
                <Wand2 />
              </Button>
            </div>
          </div>

          <div className="grid gap-4 sm:grid-cols-[1fr_1fr]">
            <div className="space-y-2">
              <Label>Domain</Label>
              <Select
                value={domainId || undefined}
                onValueChange={(value) => {
                  setDomainId(String(value || ""))
                  setError("")
                }}
                disabled={domainsLoading || domains.length === 0}
              >
                <SelectTrigger className="w-full" aria-label="Domain">
                  <SelectValue placeholder={domainsLoading ? "Loading domains…" : "Select a domain"}>
                    {(value) =>
                      domains.find((domain) => domain.id === value)?.name ??
                      (domainsLoading ? "Loading domains…" : "Select a domain")
                    }
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {domains.map((domain) => (
                    <SelectItem key={domain.id} value={domain.id}>
                      {domain.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-2">
              <Label>Name style</Label>
              <Select value={style} onValueChange={handleStyleChange}>
                <SelectTrigger className="w-full" aria-label="Random name style">
                  <SelectValue>
                    {(value) => NAME_STYLE_LABELS[(value as NameStyle) || "us"]}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="us">English</SelectItem>
                  <SelectItem value="id">Indonesian</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="rounded-xl border border-border/70 bg-muted/35 p-3">
            <div className="flex items-center justify-between gap-3">
              <span className="text-[11px] font-medium tracking-[0.12em] text-muted-foreground uppercase">
                Preview
              </span>
              <span className="inline-flex items-center gap-1.5 text-[11px] text-muted-foreground">
                <span className="signal-dot" />
                {worker?.name || "inbox-worker"}
              </span>
            </div>
            <AnimatePresence mode="popLayout" initial={false}>
              <motion.p
                key={preview}
                initial={prefersReducedMotion ? false : { opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={prefersReducedMotion ? undefined : { opacity: 0, y: -4 }}
                transition={{ duration: 0.18 }}
                className="mt-1.5 truncate font-mono text-sm font-medium"
              >
                {preview}
              </motion.p>
            </AnimatePresence>
          </div>

          {domainsError && (
            <div className="flex items-start gap-2 rounded-xl border border-amber-500/25 bg-amber-500/8 p-3 text-xs text-amber-700 dark:text-amber-300">
              <Settings2 className="mt-0.5 size-4 shrink-0" />
              <div className="space-y-1">
                <p className="font-medium">Cloudflare domains are unavailable</p>
                <p className="opacity-80">{domainsError.message}</p>
                <button
                  type="button"
                  className="inline-flex items-center gap-1 font-medium underline underline-offset-2"
                  onClick={() => {
                    setIsOpen(false)
                    navigate("/settings")
                  }}
                >
                  Open settings <ArrowRight className="size-3" />
                </button>
              </div>
            </div>
          )}

          {error && (
            <p role="alert" className="text-xs font-medium text-destructive">
              {error}
            </p>
          )}

          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <Button
              type="button"
              variant="outline"
              onClick={() => setIsOpen(false)}
              disabled={isCreating}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={isCreating || !domains.length}>
              {isCreating ? <Loader2 className="animate-spin" /> : <Check />}
              {isCreating ? "Creating…" : "Create address"}
            </Button>
          </div>

          <p className={cn("text-center text-[11px] text-muted-foreground")}>
            A literal routing rule is created for this address in{" "}
            <span className="font-medium text-foreground">
              {selectedDomain?.name || "your zone"}
            </span>
            .
          </p>
        </form>
      </DialogContent>
    </Dialog>
  )
}
