import * as React from "react"

import { CreateAddressDialog } from "@/components/create-address-dialog"
import { CreateAddressDialogContext } from "@/components/create-address-context"

export function CreateAddressProvider({ children }: { children: React.ReactNode }) {
  const [isOpen, setIsOpen] = React.useState(false)

  const value = React.useMemo(
    () => ({
      isOpen,
      setIsOpen,
      open: () => setIsOpen(true),
    }),
    [isOpen]
  )

  return (
    <CreateAddressDialogContext.Provider value={value}>
      {children}
      <CreateAddressDialog />
    </CreateAddressDialogContext.Provider>
  )
}

export { useCreateAddressDialog } from "@/components/create-address-context"
