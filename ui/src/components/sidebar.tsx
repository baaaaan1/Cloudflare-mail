import {
  ArrowUpRight,
  AtSign,
  ChevronRight,
  CircleAlert,
  CircleCheck,
  Inbox,
  LogOut,
  Plus,
  Settings2,
} from "lucide-react"
import { motion } from "motion/react"

import { Brand } from "@/components/brand"
import { NavIcon } from "@/components/nav-icon"
import { useCreateAddressDialog } from "@/components/create-address-context"
import { Button } from "@/components/ui/button"
import { ScrollArea } from "@/components/ui/scroll-area"
import { useLogout } from "@/hooks/use-logout"
import { useWorkspace } from "@/hooks/use-workspace"
import { NAV_ITEMS } from "@/lib/constants"
import { formatCompactNumber, getInitials, localPartOf } from "@/lib/format"
import { Link, navigate, useRoute } from "@/lib/router"
import { STORAGE_KEYS } from "@/lib/query-keys"
import { cn } from "cn"

type SidebarProps = {
  onNavigate?: () => void
  layoutIdPrefix?: string
  className?: string
}

export function Sidebar({
  onNavigate,
  layoutIdPrefix = "desktop",
  className,
}: SidebarProps) {
  const { pathname } = useRoute()
  const { addresses, activeAddress, setActiveAddress, totalMessages, health, healthError, session, summaryError } =
    useWorkspace()
  const { open } = useCreateAddressDialog()
  const logout = useLogout()

  const isActive = (to: string) => {
    if (to === "/") return pathname === "/"
    return pathname === to || pathname.startsWith(`${to}/`)
  }

  const selectMailbox = (address: string) => {
    setActiveAddress(address)
    localStorage.setItem(STORAGE_KEYS.activeMailbox, address)
    navigate("/inbox")
    onNavigate?.()
  }

  const go = (to: string) => {
    navigate(to)
    onNavigate?.()
  }

  const healthOk = !healthError && health?.ok !== false

  return (
    <div
      className={cn(
        "flex h-full min-h-0 flex-col bg-sidebar/85 backdrop-blur-xl",
        className
      )}
    >
      <div className="flex items-center justify-between px-4 pt-5 pb-4">
        <Link to="/" onClick={onNavigate} aria-label="Cloudflare Mail home">
          <Brand />
        </Link>
      </div>

      <div className="px-3">
        <Button
          className="h-10 w-full justify-start gap-2.5 rounded-xl shadow-md shadow-primary/20"
          onClick={() => {
            open()
            onNavigate?.()
          }}
        >
          <Plus className="size-4" />
          New address
          <kbd className="ml-auto hidden rounded-md border border-white/20 bg-white/10 px-1.5 py-0.5 text-[10px] font-medium sm:inline-block">
            N
          </kbd>
        </Button>
      </div>

      <nav className="mt-5 px-3" aria-label="Main navigation">
        <p className="mb-2 px-2 text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">
          Workspace
        </p>
        <ul className="space-y-0.5">
          {NAV_ITEMS.filter((item) => item.to !== "/destinations").map((item) => {
            const active = isActive(item.to)
            return (
              <li key={item.to}>
                <Link
                  to={item.to}
                  onClick={onNavigate}
                  className={cn(
                    "group relative flex items-center gap-3 rounded-xl px-2.5 py-2 text-[13px] font-medium transition-colors",
                    active
                      ? "text-foreground"
                      : "text-muted-foreground hover:bg-sidebar-accent/70 hover:text-foreground"
                  )}
                  aria-current={active ? "page" : undefined}
                >
                  {active && (
                    <motion.span
                      layoutId={`${layoutIdPrefix}-nav-active`}
                      className="absolute inset-0 rounded-xl bg-sidebar-accent ring-1 ring-border/60"
                      transition={{ type: "spring", stiffness: 420, damping: 34 }}
                    />
                  )}
                  <NavIcon
                    name={item.icon}
                    className={cn(
                      "relative size-4 transition-colors",
                      active ? "text-primary" : "text-muted-foreground group-hover:text-foreground"
                    )}
                  />
                  <span className="relative">{item.label}</span>
                  {item.to === "/inbox" && totalMessages > 0 && (
                    <span className="relative ml-auto rounded-full bg-primary/10 px-1.5 py-0.5 text-[10px] font-semibold text-primary tabular-nums">
                      {formatCompactNumber(totalMessages)}
                    </span>
                  )}
                </Link>
              </li>
            )
          })}
          <li>
            <Link
              to="/destinations"
              onClick={onNavigate}
              className={cn(
                "group relative flex items-center gap-3 rounded-xl px-2.5 py-2 text-[13px] font-medium transition-colors",
                isActive("/destinations")
                  ? "text-foreground"
                  : "text-muted-foreground hover:bg-sidebar-accent/70 hover:text-foreground"
              )}
            >
              {isActive("/destinations") && (
                <motion.span
                  layoutId={`${layoutIdPrefix}-nav-active`}
                  className="absolute inset-0 rounded-xl bg-sidebar-accent ring-1 ring-border/60"
                  transition={{ type: "spring", stiffness: 420, damping: 34 }}
                />
              )}
              <NavIcon
                name="destinations"
                className={cn(
                  "relative size-4",
                  isActive("/destinations") ? "text-primary" : "text-muted-foreground"
                )}
              />
              <span className="relative">Destinations</span>
            </Link>
          </li>
        </ul>
      </nav>

      <div className="mt-6 flex min-h-0 flex-1 flex-col px-3">
        <div className="mb-2 flex items-center justify-between px-2">
          <p className="text-[10px] font-semibold tracking-[0.16em] text-muted-foreground uppercase">
            Mailboxes
          </p>
          <Link
            to="/addresses"
            onClick={onNavigate}
            className="flex items-center gap-0.5 text-[10px] font-medium text-muted-foreground transition-colors hover:text-foreground"
          >
            View all <ChevronRight className="size-3" />
          </Link>
        </div>

        <ScrollArea className="min-h-0 flex-1">
          <div className="space-y-0.5 pb-3">
            <button
              type="button"
              onClick={() => selectMailbox("")}
              className={cn(
                "group flex w-full items-center gap-2.5 rounded-xl px-2.5 py-2 text-left text-[13px] transition-colors",
                !activeAddress
                  ? "bg-primary/8 font-medium text-foreground"
                  : "text-muted-foreground hover:bg-sidebar-accent/70 hover:text-foreground"
              )}
            >
              <span className="grid size-7 shrink-0 place-items-center rounded-lg bg-muted text-muted-foreground">
                <Inbox className="size-3.5" />
              </span>
              <span className="min-w-0 flex-1 truncate">All mail</span>
              <span className="text-[10px] tabular-nums">{formatCompactNumber(totalMessages)}</span>
            </button>

            {addresses.slice(0, 8).map((mailbox) => {
              const active = activeAddress === mailbox.address
              return (
                <button
                  key={mailbox.address}
                  type="button"
                  onClick={() => selectMailbox(mailbox.address)}
                  title={mailbox.address}
                  className={cn(
                    "group flex w-full items-center gap-2.5 rounded-xl px-2.5 py-2 text-left transition-colors",
                    active
                      ? "bg-primary/8 font-medium text-foreground"
                      : "text-muted-foreground hover:bg-sidebar-accent/70 hover:text-foreground"
                  )}
                >
                  <span
                    className={cn(
                      "grid size-7 shrink-0 place-items-center rounded-full text-[10px] font-semibold",
                      active
                        ? "bg-primary text-primary-foreground"
                        : "bg-muted text-muted-foreground"
                    )}
                  >
                    {getInitials(mailbox.localPart)}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-[12.5px]">
                      {localPartOf(mailbox.address)}
                    </span>
                    <span className="block truncate text-[10px] text-muted-foreground">
                      {mailbox.domain}
                    </span>
                  </span>
                  {mailbox.total > 0 && (
                    <span className="text-[10px] tabular-nums">
                      {formatCompactNumber(mailbox.total)}
                    </span>
                  )}
                </button>
              )
            })}

            {!addresses.length && (
              <div className="mx-1 rounded-xl border border-dashed border-border/80 px-3 py-4 text-center">
                <AtSign className="mx-auto size-4 text-muted-foreground" />
                <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
                  No mailboxes yet.
                  <br />
                  Create one to get started.
                </p>
              </div>
            )}

            {summaryError && (
              <p className="px-2 pt-2 text-[10px] leading-relaxed text-amber-600 dark:text-amber-400">
                Inbox storage unavailable. Check the D1 database.
              </p>
            )}
          </div>
        </ScrollArea>
      </div>

      <div className="mt-2 space-y-2 border-t border-sidebar-border px-3 py-3">
        <button
          type="button"
          onClick={() => go("/settings")}
          className="group flex w-full items-center gap-2.5 rounded-xl border border-border/70 bg-card/60 px-2.5 py-2.5 text-left transition-colors hover:border-primary/25 hover:bg-card"
        >
          <span className="relative grid size-7 shrink-0 place-items-center rounded-full bg-muted">
            {healthOk ? (
              <CircleCheck className="size-3.5 text-emerald-500" />
            ) : (
              <CircleAlert className="size-3.5 text-amber-500" />
            )}
          </span>
          <span className="min-w-0 flex-1">
            <span className="block text-[11.5px] font-medium">
              {healthOk ? "Systems normal" : "Needs attention"}
            </span>
            <span className="block truncate text-[10px] text-muted-foreground">
              {health ? `${health.destinations} destinations` : "Checking status…"}
            </span>
          </span>
          <Settings2 className="size-3.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
        </button>

        <div className="flex items-center gap-2.5 px-1 py-0.5">
          <div className="grid size-8 shrink-0 place-items-center rounded-full bg-primary/10 text-[11px] font-semibold text-primary">
            {getInitials(session?.email || "admin")}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-[11.5px] font-medium">
              {session?.email || "Administrator"}
            </p>
            <p className="text-[10px] text-muted-foreground capitalize">
              {session?.role || "admin"}
            </p>
          </div>
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label="Sign out"
            title="Sign out"
            onClick={() => logout.mutate()}
            disabled={logout.isPending}
          >
            <LogOut />
          </Button>
        </div>

        <a
          href="https://github.com/baaaaan1/Cloudflare-mail"
          target="_blank"
          rel="noreferrer"
          className="flex items-center justify-between px-1 text-[10px] text-muted-foreground transition-colors hover:text-foreground"
        >
          <span>Cloudflare Email Panel</span>
          <span className="inline-flex items-center gap-0.5">
            GitHub <ArrowUpRight className="size-3" />
          </span>
        </a>
      </div>
    </div>
  )
}

