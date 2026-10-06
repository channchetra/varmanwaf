import { create } from 'zustand'
import type { Site } from '@/api/types'

const SITE_KEY = 'pingwaf.currentSiteId'

interface SiteState {
  currentSiteId: string | null
  sites: Site[]
  setCurrentSiteId: (id: string | null) => void
  setSites: (sites: Site[]) => void
  currentSite: () => Site | undefined
}

const initialSiteId =
  typeof localStorage !== 'undefined' ? localStorage.getItem(SITE_KEY) : null

export const useSiteStore = create<SiteState>((set, get) => ({
  currentSiteId: initialSiteId,
  sites: [],
  setCurrentSiteId: (id) => {
    if (id) localStorage.setItem(SITE_KEY, id)
    else localStorage.removeItem(SITE_KEY)
    set({ currentSiteId: id })
  },
  setSites: (sites) => set({ sites }),
  currentSite: () => get().sites.find((s) => s.id === get().currentSiteId),
}))
