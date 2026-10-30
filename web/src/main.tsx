import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { reloadOnceForChunkError } from './lib/chunkReload'

// Side-effect imports: design system styles, i18n bootstrap and theme init.
import './index.css'
import './i18n'
import './stores/themeStore'

// Vite emits this when a modulepreload link points at a chunk from an old
// deployment. A single reload pulls the new index; the timestamp guard in
// `reloadOnceForChunkError` prevents a loop if the deployment itself is bad.
window.addEventListener('vite:preloadError', (event) => {
  // Only swallow the rejection when a reload is actually starting; otherwise
  // let it reach the router's error element so the user can retry manually.
  if (reloadOnceForChunkError()) event.preventDefault()
})

const rootElement = document.getElementById('root')
if (!rootElement) throw new Error('Root element #root not found')

createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
