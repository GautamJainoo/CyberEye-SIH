'use client'

import { Provider } from 'react-redux'
import { store } from '../store'
import { ThemeProvider } from '../context/ThemeContext'
import { ToastProvider } from '../components/Toast'

export default function Providers({ children }: { children: React.ReactNode }) {
  return (
    <Provider store={store}>
      <ThemeProvider>
        <ToastProvider>{children}</ToastProvider>
      </ThemeProvider>
    </Provider>
  )
}
