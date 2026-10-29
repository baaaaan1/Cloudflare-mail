import {
  ChevronDown,
  Command,
  LogOut,
  Menu,
  RefreshCw,
  Search,
  Settings2,
  UserRound,
} from "lucide-react"

import { Brand } from "@/components/brand"
import { ThemeMenu } from "@/components/theme-menu"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useLogout } from "@/hooks/use-logout"
import { useWorkspace } from "@/hooks/use-workspace"
import { NAV_ITEMS } from "@/lib/constants"
import { getInitials } from "@/lib/format"
import { Link, navigate, useRoute } from "@/lib/router"
import { cn } from "cn"

type TopbarProps = {
  onOpenMenu: () => void
  onOpenCommand: () => void
}

export function Topbar({ onOpenMenu, onOpenCommand }: TopbarProps) {
  const { pathname } = useRoute()
  const { health, healthError, session, refreshWorkspace } = useWorkspace()
  const logout = useLogout()

  const current =
    NAV_ITEMS.find((item) => {
      if (item.to === "/") return pathname === "/"
      return pathname === item.to || pathname.startsWith(`${item.to}/`)
    }) ?? NAV_ITEMS[0]

  const healthOk = !healthError && health?.ok !== false

  return (
    <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-border/60 bg-background/70 px-4 backdrop-blur-xl lg:px-8">
      <Button
        variant="ghost"
        size="icon"
        className="lg:hidden"
        onClick={onOpenMenu}
        aria-label="Open navigation"
      >
        <Menu />
      </Button>

      <div className="flex min-w-0 items-center gap-3">
        <Link to="/" className="lg:hidden" aria-label="Cloudflare Mail home">
          <Brand compact />
        </Link>
        <div className="hidden items-center gap-2 text-[13px] sm:flex">
          <span className="text-muted-foreground">Workspace</span>
          <span className="text-muted-foreground/40">/</span>
          <span className="font-medium">{current.label}</span>
        </div>
        <div className="min-w-0 sm:hidden">
          <p className="truncate text-sm font-semibold">{current.label}</p>
        </div>
      </div>

      <div className="ml-auto flex items-center gap-1.5">
        <button
          type="button"
          onClick={onOpenCommand}
          className="hidden h-9 items-center gap-2 rounded-xl border border-border/80 bg-card/60 px-3 text-[12px] text-muted-foreground transition-colors hover:border-border hover:bg-card hover:text-foreground md:flex"
          aria-label="Open command palette"
        >
          <Search className="size-3.5" />
          <span>Search or jump to…</span>
          <kbd className="ml-3 inline-flex items-center gap-0.5 rounded-md border border-border bg-muted/60 px-1.5 py-0.5 font-mono text-[10px]">
            <Command className="size-2.5" />K
          </kbd>
        </button>

        <Button
          variant="ghost"
          size="icon"
          className="md:hidden"
          onClick={onOpenCommand}
          aria-label="Search"
        >
          <Search />
        </Button>

        <div
          className={cn(
            "hidden items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium sm:flex",
            healthOk
              ? "border-emerald-500/20 bg-emerald-500/8 text-emerald-700 dark:text-emerald-300"
              : "border-amber-500/25 bg-amber-500/8 text-amber-700 dark:text-amber-300"
          )}
          title={
            health
              ? `${health.destinations} destinations · ${health.warnings.length} warnings`
              : "Checking Cloudflare status"
          }
        >
          <span
            className={cn(
              "size-1.5 rounded-full",
              healthOk ? "bg-emerald-500" : "bg-amber-500"
            )}
          />
          {healthOk ? "Connected" : "Attention"}
        </div>

        <Button
          variant="ghost"
          size="icon"
          onClick={() => void refreshWorkspace()}
          aria-label="Refresh workspace"
          title="Refresh workspace"
        >
          <RefreshCw />
        </Button>

        <ThemeMenu />

        <DropdownMenu>
          <DropdownMenuTrigger
            render={<Button variant="ghost" className="h-9 gap-2 px-1.5 sm:pr-2" />}
          >
            <span className="grid size-7 place-items-center rounded-full bg-primary/10 text-[10px] font-semibold text-primary">
              {getInitials(session?.email || "admin")}
            </span>
            <span className="hidden max-w-32 truncate text-[12px] font-medium sm:block">
              {session?.email?.split("@")[0] || "admin"}
            </span>
            <ChevronDown className="hidden size-3.5 text-muted-foreground sm:block" />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuGroup>
              <DropdownMenuLabel className="space-y-0.5 py-2">
                <span className="block text-sm font-medium text-foreground">Signed in</span>
                <span className="block truncate text-[11px] font-normal">
                  {session?.email || "Administrator"}
                </span>
              </DropdownMenuLabel>
            </DropdownMenuGroup>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => navigate("/settings")}>
              <UserRound />
              Account & settings
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => navigate("/addresses")}>
              <Settings2 />
              Manage addresses
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              variant="destructive"
              onClick={() => logout.mutate()}
              disabled={logout.isPending}
            >
              <LogOut />
              Sign out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </header>
  )
}
