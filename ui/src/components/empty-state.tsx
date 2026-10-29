import type { LucideIcon } from "lucide-react"
import type { ReactNode } from "react"
import { motion, useReducedMotion } from "motion/react"

import { cn } from "cn"

type EmptyStateProps = {
  icon: LucideIcon
  title: string
  description: string
  action?: ReactNode
  className?: string
}

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  className,
}: EmptyStateProps) {
  const prefersReducedMotion = useReducedMotion()

  return (
    <motion.div
      initial={prefersReducedMotion ? false : { opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.35, ease: [0.22, 1, 0.36, 1] }}
      className={cn(
        "flex flex-col items-center justify-center px-6 py-14 text-center",
        className
      )}
    >
      <div className="relative mb-4 grid size-14 place-items-center rounded-2xl border border-border/70 bg-muted/50">
        <div className="absolute inset-0 rounded-2xl bg-primary/5 blur-xl" />
        <Icon className="relative size-6 text-muted-foreground" strokeWidth={1.6} />
      </div>
      <h3 className="text-sm font-semibold">{title}</h3>
      <p className="mt-1 max-w-xs text-xs leading-relaxed text-muted-foreground">
        {description}
      </p>
      {action && <div className="mt-5">{action}</div>}
    </motion.div>
  )
}
