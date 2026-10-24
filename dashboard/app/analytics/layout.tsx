import type { Metadata } from 'next'
import type { ReactNode } from 'react'
import Shell from '@/components/aa/Shell'

export const metadata: Metadata = {
  title: 'xdp-sentinel — Analytics',
  description: 'Advanced traffic and attack analytics for the xdp-sentinel appliance',
}

export default function AnalyticsLayout({ children }: { children: ReactNode }) {
  return <Shell>{children}</Shell>
}
