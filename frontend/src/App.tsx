import './index.css'
import Dashboard from './pages/Dashboard'
import { ToastProvider } from './components/Toast'
import { ThemeProvider } from './context/ThemeContext'
import { Provider } from 'react-redux'
import { store } from './store'

function App() {
  return (
    <Provider store={store}>
      <ThemeProvider>
        <ToastProvider>
          <Dashboard />
        </ToastProvider>
      </ThemeProvider>
    </Provider>
  )
}

export default App
