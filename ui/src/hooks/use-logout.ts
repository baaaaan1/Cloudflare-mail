import { useMutation, useQueryClient } from "@tanstack/react-query"

import { apiClient } from "@/lib/api"
import { navigate } from "@/lib/router"

export function useLogout() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: apiClient.logout,
    onSettled: () => {
      queryClient.clear()
      navigate("/login", { replace: true })
    },
  })
}
