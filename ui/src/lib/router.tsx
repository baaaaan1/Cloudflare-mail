import * as React from "react"

const NAVIGATE_EVENT = "cfmail:navigate"

export function navigate(to: string, options: { replace?: boolean } = {}) {
  if (typeof window === "undefined") return
  const current = `${window.location.pathname}${window.location.search}`
  if (current === to) return

  if (options.replace) {
    window.history.replaceState({}, "", to)
  } else {
    window.history.pushState({}, "", to)
  }
  window.dispatchEvent(new Event(NAVIGATE_EVENT))
  window.scrollTo(0, 0)
}

export function usePathname() {
  const [pathname, setPathname] = React.useState(() =>
    typeof window === "undefined" ? "/" : window.location.pathname
  )

  React.useEffect(() => {
    const update = () => setPathname(window.location.pathname)
    window.addEventListener("popstate", update)
    window.addEventListener(NAVIGATE_EVENT, update)
    return () => {
      window.removeEventListener("popstate", update)
      window.removeEventListener(NAVIGATE_EVENT, update)
    }
  }, [])

  return pathname
}

type LinkProps = React.ComponentProps<"a"> & {
  to: string
  replace?: boolean
}

export function Link({ to, replace, onClick, ...props }: LinkProps) {
  return (
    <a
      href={to}
      onClick={(event) => {
        onClick?.(event)
        if (
          event.defaultPrevented ||
          event.button !== 0 ||
          event.metaKey ||
          event.ctrlKey ||
          event.shiftKey ||
          event.altKey
        ) {
          return
        }
        event.preventDefault()
        navigate(to, { replace })
      }}
      {...props}
    />
  )
}

export function useRoute() {
  const pathname = usePathname()
  const segments = pathname.split("/").filter(Boolean)
  const section = segments[0] || "overview"
  const messageId =
    section === "inbox" && segments[1] && /^\d+$/.test(segments[1])
      ? Number(segments[1])
      : null

  return { pathname, section, messageId }
}
