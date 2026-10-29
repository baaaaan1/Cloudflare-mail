export type TurnstileRenderOptions = {
  sitekey: string
  theme?: "light" | "dark" | "auto"
  size?: "normal" | "compact" | "flexible"
  appearance?: "always" | "execute" | "interaction-only"
  callback?: (token: string) => void
  "expired-callback"?: () => void
  "error-callback"?: () => void
}

export type TurnstileApi = {
  render: (container: HTMLElement | string, options: TurnstileRenderOptions) => string
  reset: (widgetId?: string) => void
  remove: (widgetId: string) => void
}

declare global {
  interface Window {
    turnstile?: TurnstileApi
  }
}

const SCRIPT_URL = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit"

let loader: Promise<TurnstileApi> | null = null

export function loadTurnstile(): Promise<TurnstileApi> {
  if (typeof window === "undefined") {
    return Promise.reject(new Error("Turnstile requires a browser"))
  }
  if (window.turnstile) return Promise.resolve(window.turnstile)
  if (loader) return loader

  loader = new Promise<TurnstileApi>((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>(
      'script[src^="https://challenges.cloudflare.com/turnstile"]'
    )
    const script = existing ?? document.createElement("script")

    const cleanup = () => {
      script.removeEventListener("load", handleLoad)
      script.removeEventListener("error", handleError)
    }
    const handleLoad = () => {
      cleanup()
      if (window.turnstile) resolve(window.turnstile)
      else reject(new Error("Turnstile failed to initialize"))
    }
    const handleError = () => {
      cleanup()
      reject(new Error("Could not load Turnstile"))
    }

    script.addEventListener("load", handleLoad)
    script.addEventListener("error", handleError)

    if (!existing) {
      script.src = SCRIPT_URL
      script.async = true
      script.defer = true
      document.head.appendChild(script)
    }
  }).catch((error) => {
    loader = null
    throw error
  })

  return loader
}
