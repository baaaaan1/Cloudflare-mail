import * as React from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { motion, useReducedMotion } from "motion/react"
import { CloudOff, RefreshCw } from "lucide-react"

import { AppShell } from "@/components/app-shell"
import { Brand } from "@/components/brand"
import { CreateAddressProvider } from "@/components/create-address-provider"
import { ErrorState } from "@/components/error-state"
import { WorkspaceProvider } from "@/hooks/use-workspace"
import { Button } from "@/components/ui/button"
import { apiClient } from "@/lib/api"
import { navigate, usePathname } from "@/lib/router"
import { queryKeys } from "@/lib/query-keys"
import type { AuthStatus } from "@/lib/types"
import { LoginPage } from "@/pages/login"

function BootScreen({ message = "Opening workspace" }: { message?: string }) {
  const prefersReducedMotion = useReducedMotion()

  return (
    <div className="relative grid min-h-svh place-items-center px-6">
      <div className="app-backdrop" />
      <motion.div
        initial={prefersReducedMotion ? false : { opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="flex flex-col items-center gap-5 text-center"
      >
        <div className="relative">
          <motion.div
            className="absolute -inset-4 rounded-3xl bg-primary/15 blur-2xl"
            animate={prefersReducedMotion ? undefined : { opacity: [0.5, 0.9, 0.5] }}
            transition={{ duration: 2.4, repeat: Infinity, ease: "easeInOut" }}
          />
          <Brand compact />
        </div>
        <div>
          <p className="text-sm font-medium">{message}</p>
          <p className="mt-1 text-xs text-muted-foreground">Checking your session…</p>
        </div>
        <div className="flex gap-1.5" aria-hidden="true">
          {[0, 1, 2].map((index) => (
            <motion.span
              key={index}
              className="size-1.5 rounded-full bg-primary"
              animate={prefersReducedMotion ? undefined : { opacity: [0.25, 1, 0.25] }}
              transition={{ duration: 1.1, repeat: Infinity, delay: index * 0.16 }}
            />
          ))}
        </div>
      </motion.div>
    </div>
  )
}

export function App() {
  const pathname = usePathname()
  const queryClient = useQueryClient()
  const isLoginRoute = pathname === "/login"

  const authQuery = useQuery({
    queryKey: queryKeys.auth,
    queryFn: apiClient.authStatus,
    staleTime: 30_000,
    retry: 1,
  })

  React.useEffect(() => {
    const handleUnauthorized = () => {
      queryClient.setQueryData<AuthStatus>(queryKeys.auth, (current) => ({
        loggedIn: false,
        authRequired: current?.authRequired ?? true,
        passwordEnabled: current?.passwordEnabled ?? true,
        role: current?.role,
      }))
      navigate("/login", { replace: true })
    }

    window.addEventListener("cfmail:unauthorized", handleUnauthorized)
    return () => window.removeEventListener("cfmail:unauthorized", handleUnauthorized)
  }, [queryClient])

  React.useEffect(() => {
    if (authQuery.data?.loggedIn && isLoginRoute) {
      navigate("/", { replace: true })
    } else if (authQuery.data && !authQuery.data.loggedIn && !isLoginRoute) {
      navigate("/login", { replace: true })
    }
  }, [authQuery.data, isLoginRoute])

  if (authQuery.isPending) {
    return <BootScreen />
  }

  if (authQuery.isError) {
    return (
      <div className="relative grid min-h-svh place-items-center px-5">
        <div className="app-backdrop" />
        <div className="w-full max-w-md space-y-5">
          <Brand />
          <div className="surface-card rounded-2xl p-5">
            <div className="mb-3 grid size-10 place-items-center rounded-xl bg-destructive/10 text-destructive">
              <CloudOff className="size-5" />
            </div>
            <ErrorState
              title="Could not reach the panel"
              message={authQuery.error.message}
              onRetry={() => void authQuery.refetch()}
            />
            <Button
              variant="outline"
              className="mt-3 w-full"
              onClick={() => window.location.reload()}
            >
              <RefreshCw />
              Reload page
            </Button>
          </div>
        </div>
      </div>
    )
  }

  const authStatus = authQuery.data

  if (!authStatus?.loggedIn) {
    return (
      <LoginPage
        authStatus={
          authStatus ?? {
            loggedIn: false,
            authRequired: true,
            passwordEnabled: true,
          }
        }
      />
    )
  }

  if (isLoginRoute) {
    return <BootScreen message="Taking you to your workspace" />
  }

  return (
    <WorkspaceProvider>
      <CreateAddressProvider>
        <AppShell />
      </CreateAddressProvider>
    </WorkspaceProvider>
  )
}

export default App
