import './index.css'
import Dashboard from './pages/Dashboard'
import { ToastProvider } from './components/Toast'
import { ThemeProvider } from './context/ThemeContext'

function App() {
  return (
    <ThemeProvider>
      <ToastProvider>
        <Dashboard />
      </ToastProvider>
    </ThemeProvider>
  )
}

export default App
