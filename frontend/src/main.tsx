import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import './styles/global.css'
import App from './App.tsx'
import { LanguageProvider } from './i18n/LanguageContext.tsx'
import { registerLocalFirst } from './offline/registerServiceWorker'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <LanguageProvider>
        <App />
      </LanguageProvider>
    </BrowserRouter>
  </StrictMode>,
)
registerLocalFirst() // طبقة Local-First — لا تُفعَّل إلا بـ VITE_ENABLE_LOCAL_FIRST=true
