'use client'
import { useEffect } from 'react'
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
} from '@/components/ui/command'
import Icon, { type IconName } from './icons'

export interface WallSection {
  id: string
  label: string
  group: string
  hint?: string
  icon?: IconName
}

export default function CommandMenu({
  open,
  setOpen,
  sections,
  onGo,
}: {
  open: boolean
  setOpen: (o: boolean) => void
  sections: WallSection[]
  onGo: (id: string) => void
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault()
        setOpen(!open)
      }
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, setOpen])

  const go = (id: string) => {
    setOpen(false)
    onGo(id)
  }

  const groups = Array.from(new Set(sections.map((s) => s.group)))

  return (
    <CommandDialog open={open} onOpenChange={setOpen} title="Go to section" description="Jump to a panel on the wall">
      <CommandInput placeholder="Go to a panel…" />
      <CommandList>
        <CommandEmpty>No results.</CommandEmpty>
        {groups.map((g) => (
          <CommandGroup key={g} heading={g}>
            {sections
              .filter((s) => s.group === g)
              .map((s) => (
                <CommandItem key={s.id} value={`${s.label} ${s.group}`} onSelect={() => go(s.id)} className="gap-2.5">
                  {s.icon && <Icon name={s.icon} className="h-4 w-4 text-zinc-400" />}
                  <span>{s.label}</span>
                  {s.hint && <span className="ml-auto truncate text-[11px] text-zinc-600">{s.hint}</span>}
                </CommandItem>
              ))}
          </CommandGroup>
        ))}
      </CommandList>
    </CommandDialog>
  )
}
