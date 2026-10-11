import type { IconName } from './icons'

export type ViewId = 'overview' | 'traffic' | 'security' | 'capacity' | 'telemetry'

export interface NavItem {
  id: ViewId
  label: string
  icon: IconName
}

export const NAV: { group: string; items: NavItem[] }[] = [
  {
    group: 'Monitoring',
    items: [
      { id: 'overview', label: 'Overview', icon: 'grid' },
      { id: 'traffic', label: 'Traffic & Network', icon: 'activity' },
    ],
  },
  {
    group: 'Defense',
    items: [{ id: 'security', label: 'Threats & AI', icon: 'shield' }],
  },
  {
    group: 'System',
    items: [
      { id: 'capacity', label: 'Capacity & Infra', icon: 'cpu' },
      { id: 'telemetry', label: 'Telemetry Feed', icon: 'terminal' },
    ],
  },
]

export const VIEW_META: Record<ViewId, { title: string; subtitle: string }> = {
  overview: { title: 'Overview', subtitle: 'Live posture, throughput and activity' },
  traffic: { title: 'Traffic & Network', subtitle: 'Per-interface rates · L2/L3/L4 · top talkers' },
  security: { title: 'Threats & AI', subtitle: 'TCP-flag signatures · mitigation · intelligence feed' },
  capacity: { title: 'Capacity & Infra', subtitle: 'Blocking ceiling · ML windows · switch & NIC health' },
  telemetry: { title: 'Telemetry Feed', subtitle: 'Full streaming dataplane event log' },
}
