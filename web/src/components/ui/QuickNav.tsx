import { useEffect, useState } from 'react'
import { cn } from '@/lib/utils'

export interface QuickNavItem {
  id: string
  label: string
}

/**
 * Sticky in-page quick navigation with scroll-spy. The console scrolls inside
 * `<main>`, so the sections are observed against the viewport with a band just
 * below the top edge: whichever section crosses the band is the current one.
 */
export function QuickNav({ ariaLabel, items }: { ariaLabel: string; items: QuickNavItem[] }) {
  const [active, setActive] = useState(items[0]?.id ?? '')

  useEffect(() => {
    const elements = items
      .map(({ id }) => document.getElementById(id))
      .filter((el): el is HTMLElement => el !== null)
    if (elements.length === 0) return
    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) setActive(entry.target.id)
        }
      },
      { rootMargin: '-15% 0px -75% 0px' },
    )
    for (const element of elements) observer.observe(element)
    return () => observer.disconnect()
  }, [items])

  const jump = (id: string) => {
    document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  return (
    <nav aria-label={ariaLabel} className="sticky top-2 hidden w-44 shrink-0 xl:block">
      <p className="mb-2 px-3 text-xs font-medium text-fg-subtle">{ariaLabel}</p>
      <ul className="flex flex-col border-l border-line">
        {items.map(({ id, label }) => (
          <li key={id}>
            <button
              type="button"
              onClick={() => jump(id)}
              className={cn(
                '-ml-px block w-full truncate border-l-2 px-3 py-1.5 text-left text-[13px] transition-colors',
                active === id
                  ? 'border-brand font-medium text-fg-strong'
                  : 'border-transparent text-fg-subtle hover:bg-recessed hover:text-fg',
              )}
            >
              {label}
            </button>
          </li>
        ))}
      </ul>
    </nav>
  )
}

export default QuickNav
