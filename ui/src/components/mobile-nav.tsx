import { useCreateAddressDialog } from "@/components/create-address-context"
import { NavIcon } from "@/components/nav-icon"
import { NAV_ITEMS, type NavItem } from "@/lib/constants"
import { Link, useRoute } from "@/lib/router"
import { motion } from "motion/react"
import { Plus } from "lucide-react"
import { cn } from "cn"

const ITEMS = NAV_ITEMS.filter((item) =>
  ["/", "/inbox", "/addresses", "/settings"].includes(item.to)
)

function MobileItem({ item }: { item: NavItem }) {
  const { pathname } = useRoute()
  const active =
    item.to === "/" ? pathname === "/" : pathname === item.to || pathname.startsWith(`${item.to}/`)

  return (
    <Link
      to={item.to}
      className={cn(
        "relative flex flex-col items-center justify-center gap-1 text-[10px] font-medium transition-colors",
        active ? "text-primary" : "text-muted-foreground"
      )}
      aria-current={active ? "page" : undefined}
    >
      {active && (
        <motion.span
          layoutId="mobile-nav-active"
          className="absolute inset-x-3 top-1 h-8 rounded-xl bg-primary/10"
          transition={{ type: "spring", stiffness: 420, damping: 34 }}
        />
      )}
      <NavIcon name={item.icon} className="relative size-[18px]" />
      <span className="relative">{item.shortLabel}</span>
    </Link>
  )
}

export function MobileNav() {
  const { open } = useCreateAddressDialog()

  return (
    <nav
      className="fixed inset-x-0 bottom-0 z-40 border-t border-border/70 bg-background/90 pb-[env(safe-area-inset-bottom)] backdrop-blur-xl lg:hidden"
      aria-label="Mobile navigation"
    >
      <div className="grid h-16 grid-cols-5 items-stretch">
        {ITEMS.slice(0, 2).map((item) => (
          <MobileItem key={item.to} item={item} />
        ))}
        <div className="flex items-center justify-center">
          <button
            type="button"
            onClick={open}
            className="-mt-6 grid size-12 place-items-center rounded-2xl brand-gradient text-white shadow-lg shadow-primary/30 ring-4 ring-background transition-transform active:scale-95"
            aria-label="Create a new address"
          >
            <Plus className="size-5" />
          </button>
        </div>
        {ITEMS.slice(2).map((item) => (
          <MobileItem key={item.to} item={item} />
        ))}
      </div>
    </nav>
  )
}
