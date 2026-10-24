'use client'
import { Empty } from '@/components/aa/kit'
import { Lock } from 'lucide-react'

// Shown when a signed-in user's group grants no pages (or only pages they were
// redirected away from). Requires only being logged in, so it never loops.
// 'use client' because it passes an icon component to the client <Empty>.
export default function NoAccess() {
  return (
    <Empty
      icon={Lock}
      title="No pages available"
      hint="Your account isn’t granted access to any page yet. Ask an administrator to add your group to a page."
    />
  )
}
