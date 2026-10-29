import type { LucideIcon } from "lucide-react"
import { motion, useReducedMotion } from "motion/react"

import { AnimatedNumber } from "@/components/animated-number"
import { cn } from "cn"

type StatCardProps = {
  label: string
  value: number
  icon: LucideIcon
  hint?: string
  accent?: "primary" | "blue" | "violet" | "amber" | "rose"
  index?: number
}

const ACCENT_CLASSES = {
  primary: "bg-primary/10 text-primary",
  blue: "bg-sky-500/10 text-sky-600 dark:text-sky-400",
  violet: "bg-violet-500/10 text-violet-600 dark:text-violet-400",
  amber: "bg-amber-500/10 text-amber-600 dark:text-amber-400",
  rose: "bg-rose-500/10 text-rose-600 dark:text-rose-400",
} as const

export function StatCard({
  label,
  value,
  icon: Icon,
  hint,
  accent = "primary",
  index = 0,
}: StatCardProps) {
  const prefersReducedMotion = useReducedMotion()

  return (
    <motion.div
      initial={prefersReducedMotion ? false : { opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.45, delay: index * 0.06, ease: [0.22, 1, 0.36, 1] }}
      whileHover={prefersReducedMotion ? undefined : { y: -2 }}
      className="surface-card group relative overflow-hidden rounded-2xl p-4 sm:p-5"
    >
      <div className="pointer-events-none absolute -top-10 -right-8 size-24 rounded-full bg-primary/5 blur-2xl transition-opacity group-hover:opacity-100" />
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-[11px] font-medium tracking-[0.14em] text-muted-foreground uppercase">
            {label}
          </p>
          <p className="mt-2 text-2xl font-semibold tracking-tight sm:text-3xl">
            <AnimatedNumber value={value} />
          </p>
          {hint && <p className="mt-1 text-xs text-muted-foreground">{hint}</p>}
        </div>
        <div className={cn("grid size-9 shrink-0 place-items-center rounded-xl", ACCENT_CLASSES[accent])}>
          <Icon className="size-4" />
        </div>
      </div>
    </motion.div>
  )
}
