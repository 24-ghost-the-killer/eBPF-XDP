import type { ReactNode } from 'react'

export default function Section({
  title,
  children,
  cols = 'grid-cols-1',
}: {
  title: string
  children: ReactNode
  cols?: string
}) {
  return (
    <section>
      <div className="eyebrow mb-3">{title}</div>
      <div className={`grid gap-3.5 ${cols}`}>{children}</div>
    </section>
  )
}
