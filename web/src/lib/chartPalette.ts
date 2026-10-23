import { useThemeStore } from '@/stores/themeStore'

/**
 * Theme-aware series colors for charts and topology minimaps. Recharts and
 * ReactFlow receive literal colors, so these cannot be CSS variables; the
 * palette switches with the resolved theme instead of leaving hard-coded
 * light-mode values in dark mode.
 */
export interface ChartPalette {
  requests: string
  passed: string
  blocked: string
  cache: string
  latency: string
  series: string[]
  pie: string[]
}

const LIGHT: ChartPalette = {
  requests: '#f6821f',
  passed: '#18794e',
  blocked: '#e54d2a',
  cache: '#0051c3',
  latency: '#0051c3',
  series: [
    '#f6821f',
    '#18794e',
    '#0051c3',
    '#e54d2a',
    '#8b5cf6',
    '#0891b2',
    '#ca8a04',
    '#db2777',
  ],
  pie: ['#18794e', '#0051c3', '#ffb224', '#e54d2a'],
}

const DARK: ChartPalette = {
  requests: '#ff9a4d',
  passed: '#30a46c',
  blocked: '#ff6340',
  cache: '#52a9ff',
  latency: '#52a9ff',
  series: [
    '#ff9a4d',
    '#30a46c',
    '#52a9ff',
    '#ff6340',
    '#b477e4',
    '#67e8f9',
    '#fbbf24',
    '#f472b6',
  ],
  pie: ['#30a46c', '#52a9ff', '#ffc53d', '#ff6340'],
}

export function chartPalette(resolved: 'light' | 'dark'): ChartPalette {
  return resolved === 'dark' ? DARK : LIGHT
}

export function useChartPalette(): ChartPalette {
  const resolved = useThemeStore((state) => state.resolved)
  return chartPalette(resolved)
}
