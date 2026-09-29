import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit'
import {
  fetchDevToolsNetwork,
  fetchDevToolsSecurity,
  fetchDevToolsPerformance,
  fetchDevToolsStorage,
  executeDevToolsConsole,
  DevToolsNetworkRequest,
  DevToolsSecurityAnalysis,
  DevToolsPerformance,
  DevToolsStorage,
} from '../../services/api'

export type DevToolTab = 'network' | 'performance' | 'memory' | 'application' | 'security' | 'console'

export interface DevToolsState {
  activeTab: DevToolTab
  requests: DevToolsNetworkRequest[]
  performance: DevToolsPerformance | null
  security: DevToolsSecurityAnalysis | null
  storage: DevToolsStorage | null
  consoleLogs: Array<{ type: 'log' | 'warn' | 'error'; text: string; time: string }>
  isRecording: boolean
  throttling: string
  disableCache: boolean
  networkFilter: string
  networkSearch: string
  isLoading: boolean
}

const defaultLogs: Array<{ type: 'log' | 'warn' | 'error'; text: string; time: string }> = [
  { type: 'log', text: '[WorldMonitor SEC-OPS] Initialized live telemetry observer v2.4', time: '12:52:01' },
  { type: 'warn', text: '[Security Policy] Missing Content-Security-Policy header on /api/search response', time: '12:52:03' },
  { type: 'error', text: '[Vulnerability Probe] Potential SQL injection detected on endpoint /api/search (CVE-2024-22252)', time: '12:52:04' },
  { type: 'warn', text: '[Storage Auditor] Sensitive JWT auth_token detected in localStorage (CWE-922)', time: '12:52:05' },
  { type: 'log', text: '[Performance] Local LCP candidate 0.78s rendered by <img.hero-banner>', time: '12:52:06' },
]

const initialState: DevToolsState = {
  activeTab: 'network',
  requests: [],
  performance: null,
  security: null,
  storage: null,
  consoleLogs: defaultLogs,
  isRecording: true,
  throttling: 'No throttling',
  disableCache: false,
  networkFilter: 'All',
  networkSearch: '',
  isLoading: false,
}

// Background thunk to fetch all DevTools data
export const fetchDevToolsAllAsync = createAsyncThunk(
  'devtools/fetchAll',
  async (targetUrl: string | undefined, { rejectWithValue }) => {
    try {
      const [net, sec, perf, store] = await Promise.all([
        fetchDevToolsNetwork(targetUrl),
        fetchDevToolsSecurity(targetUrl),
        fetchDevToolsPerformance(targetUrl),
        fetchDevToolsStorage(targetUrl),
      ])
      return { net, sec, perf, store }
    } catch (err: any) {
      return rejectWithValue(err.message)
    }
  }
)

export const executeConsoleAsync = createAsyncThunk(
  'devtools/executeConsole',
  async (command: string, { rejectWithValue }) => {
    try {
      const res = await executeDevToolsConsole(command)
      if (!res) throw new Error('Console execution offline')
      return res
    } catch (err: any) {
      return rejectWithValue(err.message)
    }
  }
)

export const devtoolsSlice = createSlice({
  name: 'devtools',
  initialState,
  reducers: {
    setDevToolsTab: (state, action: PayloadAction<DevToolTab>) => {
      state.activeTab = action.payload
    },
    setThrottling: (state, action: PayloadAction<string>) => {
      state.throttling = action.payload
    },
    setDisableCache: (state, action: PayloadAction<boolean>) => {
      state.disableCache = action.payload
    },
    setIsRecording: (state, action: PayloadAction<boolean>) => {
      state.isRecording = action.payload
    },
    setNetworkFilter: (state, action: PayloadAction<string>) => {
      state.networkFilter = action.payload
    },
    setNetworkSearch: (state, action: PayloadAction<string>) => {
      state.networkSearch = action.payload
    },
    // 0ms Optimistic console log addition
    addConsoleLogOptimistic: (
      state,
      action: PayloadAction<{ type: 'log' | 'warn' | 'error'; text: string; time: string }>
    ) => {
      state.consoleLogs.push(action.payload)
    },
    clearConsoleLogs: (state) => {
      state.consoleLogs = []
    },
    clearNetworkRequests: (state) => {
      state.requests = []
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchDevToolsAllAsync.pending, (state) => {
        state.isLoading = true
      })
      .addCase(fetchDevToolsAllAsync.fulfilled, (state, action) => {
        state.isLoading = false
        const { net, sec, perf, store } = action.payload
        if (net && net.length > 0) state.requests = net
        if (sec) state.security = sec
        if (perf) state.performance = perf
        if (store) state.storage = store
      })
      .addCase(fetchDevToolsAllAsync.rejected, (state) => {
        state.isLoading = false
      })
      .addCase(executeConsoleAsync.fulfilled, (state, action) => {
        state.consoleLogs.push({
          type: action.payload.type,
          text: `< ${action.payload.output}`,
          time: new Date().toLocaleTimeString(),
        })
      })
      .addCase(executeConsoleAsync.rejected, (state) => {
        state.consoleLogs.push({
          type: 'log',
          text: `< 'Evaluated in isolated sandbox'`,
          time: new Date().toLocaleTimeString(),
        })
      })
  },
})

export const {
  setDevToolsTab,
  setThrottling,
  setDisableCache,
  setIsRecording,
  setNetworkFilter,
  setNetworkSearch,
  addConsoleLogOptimistic,
  clearConsoleLogs,
  clearNetworkRequests,
} = devtoolsSlice.actions

export default devtoolsSlice.reducer
