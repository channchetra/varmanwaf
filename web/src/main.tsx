import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'

// Side-effect imports: design system styles, i18n bootstrap and theme init.
import './index.css'
import './i18n'
import './stores/themeStore'

const rootElement = document.getElementById('root')
if (!rootElement) throw new Error('Root element #root not found')

createRoot(rootElement).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
