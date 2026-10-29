import { motion } from "motion/react"

import { formatRelativeTime, getInitials, parseSender, avatarTone } from "@/lib/format"
import type { EmailSummaryItem } from "@/lib/types"
import { cn } from "cn"

type MessageListItemProps = {
  email: EmailSummaryItem
  active?: boolean
  read?: boolean
  compact?: boolean
  index?: number
  onClick: () => void
}

export function MessageListItem({
  email,
  active = false,
  read = true,
  compact = false,
  index = 0,
  onClick,
}: MessageListItemProps) {
  const sender = parseSender(email.sender)
  const subject = email.subject?.trim() || "(No subject)"
  const initials = getInitials(sender.label)

  return (
    <motion.button
      type="button"
      layout="position"
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{
        duration: 0.3,
        delay: Math.min(index, 8) * 0.035,
        ease: [0.22, 1, 0.36, 1],
      }}
      onClick={onClick}
      aria-current={active ? "true" : undefined}
      className={cn(
        "group relative flex w-full items-start gap-3 rounded-xl text-left transition-colors",
        compact ? "px-3 py-2.5" : "px-3 py-3.5",
        active
          ? "bg-primary/8 ring-1 ring-primary/15"
          : "hover:bg-muted/60"
      )}
    >
      <span
        className={cn(
          "relative grid shrink-0 place-items-center rounded-full text-[11px] font-semibold",
          compact ? "size-8" : "size-9",
          avatarTone(sender.email || sender.label)
        )}
      >
        {initials}
        {!read && (
          <span className="absolute -top-0.5 -right-0.5 size-2.5 rounded-full border-2 border-card bg-primary" />
        )}
      </span>

      <span className="min-w-0 flex-1">
        <span className="flex items-baseline justify-between gap-3">
          <span
            className={cn(
              "truncate text-[12.5px]",
              read ? "font-medium text-foreground" : "font-semibold text-foreground"
            )}
          >
            {sender.label}
          </span>
          <span className="shrink-0 text-[10px] whitespace-nowrap text-muted-foreground">
            {formatRelativeTime(email.created_at)}
          </span>
        </span>
        <span
          className={cn(
            "mt-0.5 block truncate text-[12.5px]",
            read ? "text-foreground/80" : "font-medium text-foreground"
          )}
        >
          {subject}
        </span>
        {!compact && (
          <span className="mt-1 flex items-center gap-2">
            <span className="truncate font-mono text-[10px] text-muted-foreground">
              {sender.email || "unknown sender"}
            </span>
            <span className="h-1 w-1 shrink-0 rounded-full bg-border" />
            <span className="truncate text-[10px] text-muted-foreground">
              to {email.recipient || "unknown"}
            </span>
          </span>
        )}
      </span>
    </motion.button>
  )
}
