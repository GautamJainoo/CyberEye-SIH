'use client'

import { createContext, useContext, useCallback, ReactNode } from 'react'

type ToastType = 'success' | 'error' | 'warning' | 'info'

interface ToastContextValue {
  toast: (type: ToastType, title: string, message?: string) => void
}

const ToastContext = createContext<ToastContextValue>({ toast: () => {} })

export function useToast() {
  return useContext(ToastContext)
}

export function ToastProvider({ children }: { children: ReactNode }) {
  // Disabled intrusive bottom toast popups as requested:
  // "aabhi ke lite tost message remove kar do sab me"
  // Inline UI feedback (like "Copied" checkmarks, button state changes, modal progress) is used instead.
  const toast = useCallback((_type: ToastType, _title: string, _message?: string) => {
    // Intentionally no-op to keep UI clean and distraction-free
  }, [])

  return (
    <ToastContext.Provider value={{ toast }}>
      {children}
    </ToastContext.Provider>
  )
}
