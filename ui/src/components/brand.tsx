import { Mail } from "lucide-react"

import { cn } from "cn"

type BrandProps = {
  className?: string
  compact?: boolean
}

export function Brand({ className, compact = false }: BrandProps) {
  return (
    <div className={cn("flex items-center gap-3", className)}>
      <div className="relative grid size-10 shrink-0 place-items-center rounded-2xl brand-gradient text-white shadow-lg shadow-primary/30">
        <Mail className="size-[18px]" strokeWidth={2.2} />
        <span className="absolute -right-0.5 -bottom-0.5 size-2.5 rounded-full border-2 border-card bg-primary" />
      </div>
      {!compact && (
        <div className="min-w-0">
          <div className="truncate text-[15px] leading-tight font-semibold tracking-tight">
            Cloudflare Mail
          </div>
          <div className="mt-0.5 text-[10px] font-medium tracking-[0.16em] text-muted-foreground uppercase">
            Email panel
          </div>
        </div>
      )}
    </div>
  )
}
