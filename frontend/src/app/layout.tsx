import type { Metadata } from 'next'
import '../index.css'
import Providers from './providers'

export const metadata: Metadata = {
  title: 'CyberEye',
  description: 'Evidence-backed security assessment dashboard (SIH 2026, PS 26163)',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  )
}
