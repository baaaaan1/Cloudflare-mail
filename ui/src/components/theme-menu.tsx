import { Check, Monitor, Moon, Palette, Sun } from "lucide-react"
import { motion } from "motion/react"

import { useTheme } from "@/components/theme-provider"
import { Button } from "@/components/ui/button"
import {
  Popover,
  PopoverContent,
  PopoverHeader,
  PopoverTitle,
  PopoverTrigger,
} from "@/components/ui/popover"
import { ACCENT_PRESETS } from "@/lib/constants"
import { cn } from "cn"

const THEME_OPTIONS = [
  { value: "light" as const, label: "Light", icon: Sun },
  { value: "dark" as const, label: "Dark", icon: Moon },
  { value: "system" as const, label: "System", icon: Monitor },
]

export function ThemeMenu() {
  const { theme, setTheme, accentId, setAccent } = useTheme()
  const ActiveIcon =
    theme === "dark" ? Moon : theme === "light" ? Sun : Monitor

  return (
    <Popover>
      <PopoverTrigger
        render={<Button variant="ghost" size="icon" aria-label="Appearance settings" />}
      >
        <ActiveIcon className="size-4" />
      </PopoverTrigger>
      <PopoverContent align="end" className="w-[268px] p-3">
        <PopoverHeader className="px-1 pb-1">
          <PopoverTitle className="flex items-center gap-2 text-sm">
            <Palette className="size-3.5 text-primary" />
            Appearance
          </PopoverTitle>
        </PopoverHeader>

        <div className="grid grid-cols-3 gap-1 rounded-xl bg-muted/60 p-1">
          {THEME_OPTIONS.map((option) => {
            const Icon = option.icon
            const active = theme === option.value
            return (
              <button
                key={option.value}
                type="button"
                onClick={() => setTheme(option.value)}
                aria-pressed={active}
                className={cn(
                  "relative flex flex-col items-center gap-1.5 rounded-lg px-2 py-2.5 text-[11px] font-medium transition-colors",
                  active
                    ? "bg-background text-foreground shadow-sm"
                    : "text-muted-foreground hover:text-foreground"
                )}
              >
                <Icon className="size-4" />
                {option.label}
              </button>
            )
          })}
        </div>

        <div className="mt-2 space-y-2 px-1">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-medium tracking-[0.12em] text-muted-foreground uppercase">
              Accent
            </span>
            <span className="text-[11px] text-muted-foreground capitalize">
              {accentId === "custom" ? "Custom" : accentId}
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {ACCENT_PRESETS.map((preset) => {
              const active = accentId === preset.id
              return (
                <motion.button
                  key={preset.id}
                  type="button"
                  onClick={() => setAccent(preset.id)}
                  whileHover={{ scale: 1.12 }}
                  whileTap={{ scale: 0.94 }}
                  aria-label={`${preset.name} accent`}
                  aria-pressed={active}
                  className={cn(
                    "relative grid size-7 place-items-center rounded-full ring-offset-2 ring-offset-popover transition-shadow",
                    active ? "ring-2 ring-foreground/40" : "ring-1 ring-black/5"
                  )}
                  style={{ backgroundColor: preset.swatch }}
                >
                  {active && <Check className="size-3.5 text-white drop-shadow" />}
                </motion.button>
              )
            })}
          </div>
        </div>
      </PopoverContent>
    </Popover>
  )
}
