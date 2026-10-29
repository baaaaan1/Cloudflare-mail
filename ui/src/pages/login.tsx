import * as React from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import {
  ArrowRight,
  Check,
  Eye,
  EyeOff,
  Inbox,
  KeyRound,
  Loader2,
  LockKeyhole,
  Mail,
  ShieldCheck,
  Sparkles,
  Zap,
} from "lucide-react"
import { motion, useReducedMotion } from "motion/react"

import { Brand } from "@/components/brand"
import { ThemeMenu } from "@/components/theme-menu"
import { useTheme } from "@/components/theme-provider"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { apiClient } from "@/lib/api"
import { navigate } from "@/lib/router"
import { queryKeys } from "@/lib/query-keys"
import { loadTurnstile } from "@/lib/turnstile"
import type { AuthStatus } from "@/lib/types"

type LoginPageProps = {
  authStatus: AuthStatus
}

const FEATURES = [
  {
    icon: Inbox,
    title: "A calm inbox for every alias",
    description: "Messages land in D1 and show up here instantly, with HTML and text views.",
  },
  {
    icon: Zap,
    title: "Instant routing control",
    description: "Create literal rules, pause them, or drop mail — without touching the dashboard.",
  },
  {
    icon: ShieldCheck,
    title: "Locked down by default",
    description: "Password sessions, rate limiting, and strict security headers on every request.",
  },
]

export function LoginPage({ authStatus }: LoginPageProps) {
  const queryClient = useQueryClient()
  const prefersReducedMotion = useReducedMotion()
  const { resolvedTheme } = useTheme()
  const [password, setPassword] = React.useState("")
  const [visible, setVisible] = React.useState(false)
  const [error, setError] = React.useState("")
  const [captchaToken, setCaptchaToken] = React.useState("")
  const [captchaError, setCaptchaError] = React.useState("")
  const captchaContainer = React.useRef<HTMLDivElement>(null)
  const captchaWidget = React.useRef<string | null>(null)

  const turnstileEnabled = Boolean(
    authStatus.turnstileEnabled && authStatus.turnstileSiteKey
  )

  React.useEffect(() => {
    if (!turnstileEnabled) return
    const container = captchaContainer.current
    if (!container) return
    let cancelled = false
    setCaptchaToken("")
    setCaptchaError("")

    loadTurnstile()
      .then((turnstile) => {
        if (cancelled) return
        if (captchaWidget.current) {
          try {
            turnstile.remove(captchaWidget.current)
          } catch {
            /* ignore */
          }
        }
        captchaWidget.current = turnstile.render(container, {
          sitekey: authStatus.turnstileSiteKey as string,
          theme: resolvedTheme === "dark" ? "dark" : "light",
          callback: (token) => {
            setCaptchaToken(token)
            setCaptchaError("")
            setError("")
          },
          "expired-callback": () => setCaptchaToken(""),
          "error-callback": () => {
            setCaptchaToken("")
            setCaptchaError("Captcha failed. Please refresh the page.")
          },
        })
      })
      .catch((loadError: Error) => {
        if (!cancelled) setCaptchaError(loadError.message || "Could not load captcha.")
      })

    return () => {
      cancelled = true
      const widgetId = captchaWidget.current
      captchaWidget.current = null
      if (widgetId && window.turnstile) {
        try {
          window.turnstile.remove(widgetId)
        } catch {
          /* ignore */
        }
      }
      container.innerHTML = ""
    }
  }, [turnstileEnabled, authStatus.turnstileSiteKey, resolvedTheme])

  const loginMutation = useMutation({
    mutationFn: (input: { password: string; token?: string }) =>
      apiClient.login(input.password, input.token),
    onSuccess: () => {
      queryClient.setQueryData(queryKeys.auth, {
        ...authStatus,
        loggedIn: true,
      })
      void queryClient.invalidateQueries({ queryKey: queryKeys.session })
      navigate("/", { replace: true })
    },
    onError: (loginError: Error) => {
      setError(loginError.message || "Could not sign in.")
      setCaptchaToken("")
      if (captchaWidget.current && window.turnstile) {
        try {
          window.turnstile.reset(captchaWidget.current)
        } catch {
          /* ignore */
        }
      }
    },
  })

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    if (!password) {
      setError("Enter the panel password.")
      return
    }
    if (turnstileEnabled && !captchaToken) {
      setError("Complete the captcha before signing in.")
      return
    }
    setError("")
    loginMutation.mutate({ password, token: captchaToken || undefined })
  }

  return (
    <div className="relative min-h-svh overflow-hidden">
      <div className="app-backdrop" />
      <div className="pointer-events-none absolute inset-0 overflow-hidden" aria-hidden="true">
        <motion.div
          className="aurora-blob top-[-14%] left-[8%] size-[420px] bg-primary/25"
          animate={
            prefersReducedMotion
              ? undefined
              : { x: [0, 46, -12, 0], y: [0, 34, -18, 0], scale: [1, 1.12, 0.96, 1] }
          }
          transition={{ duration: 22, repeat: Infinity, ease: "easeInOut" }}
        />
        <motion.div
          className="aurora-blob top-[36%] right-[-8%] size-[380px] bg-chart-3/15"
          animate={
            prefersReducedMotion
              ? undefined
              : { x: [0, -36, 18, 0], y: [0, -28, 24, 0], scale: [1, 0.94, 1.1, 1] }
          }
          transition={{ duration: 26, repeat: Infinity, ease: "easeInOut" }}
        />
        <motion.div
          className="aurora-blob bottom-[-18%] left-[38%] size-[420px] bg-chart-2/15"
          animate={
            prefersReducedMotion
              ? undefined
              : { x: [0, 28, -24, 0], y: [0, -22, 18, 0], scale: [1, 1.08, 0.95, 1] }
          }
          transition={{ duration: 30, repeat: Infinity, ease: "easeInOut" }}
        />
      </div>

      <div className="absolute top-4 right-4 z-20">
        <ThemeMenu />
      </div>

      <div className="relative mx-auto grid min-h-svh w-full max-w-6xl items-center gap-10 px-5 py-10 lg:grid-cols-[1.15fr_0.85fr] lg:px-8">
        <motion.div
          initial={prefersReducedMotion ? false : { opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
          className="hidden lg:block"
        >
          <Brand />
          <h1 className="mt-10 max-w-lg text-4xl leading-[1.08] font-semibold tracking-tight text-balance xl:text-[46px]">
            Your Cloudflare mail, <span className="text-gradient">beautifully in order.</span>
          </h1>
          <p className="mt-4 max-w-md text-[15px] leading-relaxed text-muted-foreground">
            One quiet control room for Email Routing, destinations, rules, and the inbox that
            catches everything.
          </p>

          <div className="mt-9 space-y-4">
            {FEATURES.map((feature, index) => {
              const Icon = feature.icon
              return (
                <motion.div
                  key={feature.title}
                  initial={prefersReducedMotion ? false : { opacity: 0, x: -14 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{
                    duration: 0.5,
                    delay: 0.2 + index * 0.1,
                    ease: [0.22, 1, 0.36, 1],
                  }}
                  className="flex max-w-md items-start gap-3"
                >
                  <span className="grid size-9 shrink-0 place-items-center rounded-xl border border-border/70 bg-card/70 text-primary shadow-sm backdrop-blur">
                    <Icon className="size-4" />
                  </span>
                  <div>
                    <p className="text-[13px] font-medium">{feature.title}</p>
                    <p className="mt-0.5 text-[12px] leading-relaxed text-muted-foreground">
                      {feature.description}
                    </p>
                  </div>
                </motion.div>
              )
            })}
          </div>

          <div className="mt-10 flex items-center gap-3 text-[11px] text-muted-foreground">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-border/70 bg-card/60 px-2.5 py-1 backdrop-blur">
              <span className="signal-dot" />
              Self-hosted
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-border/70 bg-card/60 px-2.5 py-1 backdrop-blur">
              <LockKeyhole className="size-3" />
              Password protected
            </span>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-border/70 bg-card/60 px-2.5 py-1 backdrop-blur">
              <Mail className="size-3" />
              D1 powered
            </span>
          </div>
        </motion.div>

        <motion.div
          initial={prefersReducedMotion ? false : { opacity: 0, y: 24, scale: 0.985 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 0.6, delay: 0.08, ease: [0.22, 1, 0.36, 1] }}
          className="mx-auto w-full max-w-md"
        >
          <div className="mb-6 flex items-center justify-between lg:hidden">
            <Brand />
          </div>

          <div className="surface-card relative overflow-hidden rounded-3xl p-6 sm:p-8">
            <div className="pointer-events-none absolute -top-20 -right-12 size-48 rounded-full bg-primary/15 blur-3xl" />

            <div className="relative">
              <div className="mb-6 flex size-11 items-center justify-center rounded-2xl brand-gradient text-white shadow-lg shadow-primary/25">
                <KeyRound className="size-5" />
              </div>
              <h2 className="text-2xl font-semibold tracking-tight">Welcome back</h2>
              <p className="mt-1.5 text-sm text-muted-foreground">
                Enter the panel password to open your workspace.
              </p>

              {!authStatus.passwordEnabled && (
                <div className="mt-5 rounded-xl border border-amber-500/25 bg-amber-500/8 p-3 text-[11px] leading-relaxed text-amber-700 dark:text-amber-300">
                  <p className="flex items-center gap-1.5 font-medium">
                    <Sparkles className="size-3.5" />
                    Password not configured
                  </p>
                  <p className="mt-1">
                    Add <span className="font-mono">APP_PASSWORD=…</span> to your{" "}
                    <span className="font-mono">.env</span> file and restart the server.
                  </p>
                </div>
              )}

              <form onSubmit={submit} className="mt-6 space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="panel-password">Password</Label>
                  <div className="relative">
                    <LockKeyhole className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
                    <Input
                      id="panel-password"
                      type={visible ? "text" : "password"}
                      value={password}
                      onChange={(event) => {
                        setPassword(event.target.value)
                        setError("")
                      }}
                      placeholder="Panel password"
                      className="h-11 pr-11 pl-9"
                      autoComplete="current-password"
                      autoFocus
                      aria-invalid={Boolean(error)}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon-sm"
                      className="absolute top-1/2 right-1 -translate-y-1/2"
                      onClick={() => setVisible((current) => !current)}
                      aria-label={visible ? "Hide password" : "Show password"}
                    >
                      {visible ? <EyeOff /> : <Eye />}
                    </Button>
                  </div>
                  {error && (
                    <p role="alert" className="text-xs font-medium text-destructive">
                      {error}
                    </p>
                  )}
                </div>

                {turnstileEnabled && (
                  <div className="space-y-2">
                    <div
                      ref={captchaContainer}
                      className="flex min-h-[65px] justify-center"
                      aria-label="Captcha verification"
                    />
                    {captchaError && (
                      <p role="alert" className="text-xs font-medium text-destructive">
                        {captchaError}
                      </p>
                    )}
                    <p className="text-center text-[10px] text-muted-foreground">
                      Protected by Cloudflare Turnstile
                    </p>
                  </div>
                )}

                <Button
                  type="submit"
                  size="lg"
                  className="h-11 w-full"
                  disabled={loginMutation.isPending || !authStatus.passwordEnabled}
                >
                  {loginMutation.isPending ? (
                    <>
                      <Loader2 className="animate-spin" />
                      Signing in…
                    </>
                  ) : (
                    <>
                      Open workspace
                      <ArrowRight />
                    </>
                  )}
                </Button>
              </form>

              <div className="mt-6 flex items-center gap-2 rounded-xl border border-border/70 bg-muted/25 p-3 text-[10px] leading-relaxed text-muted-foreground">
                <Check className="size-3.5 shrink-0 text-emerald-500" />
                <span>
                  Sessions are signed, HTTP-only cookies and expire after 7 days. Failed attempts are
                  rate limited and temporarily locked out.
                </span>
              </div>
            </div>
          </div>

          <p className="mt-5 text-center text-[10px] text-muted-foreground">
            Cloudflare Email Panel · Self-hosted · v1.1.0
          </p>
        </motion.div>
      </div>
    </div>
  )
}

