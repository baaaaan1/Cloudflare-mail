import * as React from "react"

type CreateAddressDialogContextValue = {
  isOpen: boolean
  setIsOpen: (open: boolean) => void
  open: () => void
}

export const CreateAddressDialogContext =
  React.createContext<CreateAddressDialogContextValue | null>(null)

export function useCreateAddressDialog() {
  const context = React.useContext(CreateAddressDialogContext)
  if (!context) {
    throw new Error("useCreateAddressDialog must be used within CreateAddressProvider")
  }
  return context
}
