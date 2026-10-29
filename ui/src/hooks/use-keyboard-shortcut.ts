import * as React from "react"

export function useKeyboardShortcut(
  shortcut: { key: string; meta?: boolean; shift?: boolean },
  handler: (event: KeyboardEvent) => void,
  options: { enabled?: boolean } = {}
) {
  const handlerRef = React.useRef(handler)

  React.useEffect(() => {
    handlerRef.current = handler
  }, [handler])

  React.useEffect(() => {
    if (options.enabled === false) return undefined
    const onKeyDown = (event: KeyboardEvent) => {
      const metaPressed = event.metaKey || event.ctrlKey
      if (shortcut.meta && !metaPressed) return
      if (!shortcut.meta && metaPressed) return
      if (shortcut.shift && !event.shiftKey) return
      if (!shortcut.shift && event.shiftKey) return
      if (event.key.toLowerCase() !== shortcut.key.toLowerCase()) return
      handlerRef.current(event)
    }

    window.addEventListener("keydown", onKeyDown)
    return () => window.removeEventListener("keydown", onKeyDown)
  }, [options.enabled, shortcut.key, shortcut.meta, shortcut.shift])
}
