import * as React from "react"

/**
 * Radix portals render into document.body by default, which is OUTSIDE the `.admin-ui`
 * scope that carries the shadcn tokens and the scoped reset. AdminShell provides its root
 * element here so every dialog / select / menu / tooltip mounts inside that scope.
 */
export const PortalContainerContext = React.createContext<HTMLElement | null>(null)

export function usePortalContainer(): HTMLElement | undefined {
  return React.useContext(PortalContainerContext) ?? undefined
}
