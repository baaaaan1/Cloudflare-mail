import * as React from "react"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"

import { apiClient } from "@/lib/api"
import { queryKeys } from "@/lib/query-keys"
import { navigate } from "@/lib/router"
import type { CreateAddressPayload } from "@/lib/types"
import { useWorkspace } from "@/hooks/use-workspace"

type CreateAddressResult = {
  address: string
  persisted: boolean
}

export function useCreateAddress(options: { onCreated?: (address: string) => void } = {}) {
  const queryClient = useQueryClient()
  const { workers, addSavedAddress, setActiveAddress } = useWorkspace()
  const { onCreated } = options

  const mutation = useMutation({
    mutationFn: async (payload: CreateAddressPayload): Promise<CreateAddressResult> => {
      const worker =
        workers.find((item) => /inbox/i.test(item.name || "")) ?? workers[0]
      const workerName = worker?.name || "inbox-worker"
      const address = `${payload.localPart.trim()}@${payload.domain.name}`.toLowerCase()

      await apiClient.createRule({
        customEmail: address,
        destinationIdManual: workerName,
        type: "worker",
        zoneId: payload.domain.id,
      })

      let persisted = true
      try {
        await apiClient.saveAddress(address)
      } catch {
        persisted = false
      }

      return { address, persisted }
    },
    onSuccess: async ({ address, persisted }, payload) => {
      addSavedAddress(address)
      setActiveAddress(address)
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.rules(payload.domain.id) }),
        queryClient.invalidateQueries({ queryKey: queryKeys.inboxSummary }),
        queryClient.invalidateQueries({ queryKey: queryKeys.latestAddress }),
        queryClient.invalidateQueries({ queryKey: ["inbox"] }),
      ])
      onCreated?.(address)
      toast.success(`Address created`, {
        description: persisted
          ? `${address} is ready to receive mail.`
          : `${address} is ready. Inbox storage is not configured yet.`,
        action: {
          label: "View inbox",
          onClick: () => {
            navigate("/inbox")
          },
        },
      })
    },
    onError: (error: Error) => {
      toast.error("Could not create address", { description: error.message })
    },
  })

  const createAddress = React.useCallback(
    (payload: CreateAddressPayload) => mutation.mutateAsync(payload),
    [mutation]
  )

  return {
    createAddress,
    isCreating: mutation.isPending,
    error: mutation.error as Error | null,
    reset: mutation.reset,
  }
}
