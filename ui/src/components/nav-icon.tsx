import {
  AtSign,
  Braces,
  Inbox,
  LayoutDashboard,
  Route,
  Send,
  Settings,
} from "lucide-react"

import type { NavItem } from "@/lib/constants"

const ICONS = {
  overview: LayoutDashboard,
  inbox: Inbox,
  addresses: AtSign,
  rules: Route,
  destinations: Send,
  api: Braces,
  settings: Settings,
} as const

export function NavIcon({
  name,
  className,
}: {
  name: NavItem["icon"]
  className?: string
}) {
  const Icon = ICONS[name]
  return <Icon className={className} />
}
