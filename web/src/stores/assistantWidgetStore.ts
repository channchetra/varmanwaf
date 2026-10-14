import { create } from 'zustand'

/**
 * Open/closed state of the floating AI assistant panel. Shared by both
 * entry points (the bottom-right floating ball and the header button) so
 * they always drive the same panel instance.
 */
interface AssistantWidgetState {
  open: boolean
  toggle: () => void
  close: () => void
}

export const useAssistantWidgetStore = create<AssistantWidgetState>((set) => ({
  open: false,
  toggle: () => set((s) => ({ open: !s.open })),
  close: () => set({ open: false }),
}))
