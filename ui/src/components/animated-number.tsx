import * as React from "react"
import { animate, useReducedMotion } from "motion/react"

import { formatCompactNumber } from "@/lib/format"

type AnimatedNumberProps = {
  value: number
  className?: string
  duration?: number
}

export function AnimatedNumber({ value, className, duration = 0.9 }: AnimatedNumberProps) {
  const prefersReducedMotion = useReducedMotion()
  const [display, setDisplay] = React.useState(value)
  const currentRef = React.useRef(value)

  React.useEffect(() => {
    if (prefersReducedMotion) {
      currentRef.current = value
      setDisplay(value)
      return undefined
    }

    const controls = animate(currentRef.current, value, {
      duration,
      ease: [0.22, 1, 0.36, 1],
      onUpdate: (latest) => {
        currentRef.current = latest
        setDisplay(Math.round(latest))
      },
    })

    return () => controls.stop()
  }, [duration, prefersReducedMotion, value])

  return <span className={className}>{formatCompactNumber(display)}</span>
}
