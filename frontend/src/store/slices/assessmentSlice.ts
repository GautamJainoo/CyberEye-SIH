import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit'
import {
  fetchHealth,
  triggerScan,
  configureTarget,
  resetDatabase,
  BackendHealth,
  ScanResponse,
  TargetConfigPayload,
  TargetConfigResponse,
} from '../../services/api'

export interface AssessmentState {
  targetUrl: string
  activeTab: string
  lastScanTime: string
  scanModalOpen: boolean
  isScanning: boolean
  backendHealth: BackendHealth | null
  scanResults: ScanResponse | null
  error: string | null
}

const initialState: AssessmentState = {
  targetUrl: 'http://127.0.0.1:3000',
  activeTab: 'dashboard',
  lastScanTime: '',
  scanModalOpen: false,
  isScanning: false,
  backendHealth: null,
  scanResults: null,
  error: null,
}

// Background Thunks
export const fetchHealthAsync = createAsyncThunk(
  'assessment/fetchHealth',
  async (_, { rejectWithValue }) => {
    try {
      const data = await fetchHealth()
      if (!data) throw new Error('Backend healthcheck unreachable')
      return data
    } catch (err: any) {
      return rejectWithValue(err.message)
    }
  }
)

export const triggerScanAsync = createAsyncThunk(
  'assessment/triggerScan',
  async (
    { profile = 'lite', tools }: { profile?: string; tools?: string[] },
    { rejectWithValue }
  ) => {
    try {
      const res = await triggerScan(profile, tools)
      if (!res) throw new Error('Scan orchestration failed')
      return res
    } catch (err: any) {
      return rejectWithValue(err.message)
    }
  }
)

export const configureTargetAsync = createAsyncThunk(
  'assessment/configureTarget',
  async (payload: TargetConfigPayload, { rejectWithValue }) => {
    try {
      const res = await configureTarget(payload)
      if (!res) throw new Error('Target configuration failed')
      return res
    } catch (err: any) {
      return rejectWithValue(err.message)
    }
  }
)

export const resetDatabaseAsync = createAsyncThunk(
  'assessment/resetDatabase',
  async (_, { rejectWithValue }) => {
    try {
      const res = await resetDatabase()
      if (!res) throw new Error('Database reset failed')
      return res
    } catch (err: any) {
      return rejectWithValue(err.message)
    }
  }
)

export const assessmentSlice = createSlice({
  name: 'assessment',
  initialState,
  reducers: {
    // 0ms Optimistic target change
    setTargetUrl: (state, action: PayloadAction<string>) => {
      state.targetUrl = action.payload
    },
    setActiveTab: (state, action: PayloadAction<string>) => {
      state.activeTab = action.payload
    },
    setLastScanTime: (state, action: PayloadAction<string>) => {
      state.lastScanTime = action.payload
    },
    setScanModalOpen: (state, action: PayloadAction<boolean>) => {
      state.scanModalOpen = action.payload
    },
    setIsScanning: (state, action: PayloadAction<boolean>) => {
      state.isScanning = action.payload
    },
  },
  extraReducers: (builder) => {
    builder
      // Health
      .addCase(fetchHealthAsync.fulfilled, (state, action) => {
        state.backendHealth = action.payload
      })
      // Trigger Scan
      .addCase(triggerScanAsync.pending, (state) => {
        state.isScanning = true
        state.error = null
      })
      .addCase(triggerScanAsync.fulfilled, (state, action) => {
        state.isScanning = false
        state.scanResults = action.payload
        state.lastScanTime = new Date().toLocaleString('en-GB', {
          day: 'numeric',
          month: 'short',
          year: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
        })
      })
      .addCase(triggerScanAsync.rejected, (state, action) => {
        state.isScanning = false
        state.error = (action.payload as string) || 'Scan failed'
      })
      // Configure target
      .addCase(configureTargetAsync.fulfilled, (state, action: PayloadAction<TargetConfigResponse>) => {
        if (action.payload.website_url) {
          state.targetUrl = action.payload.website_url
        }
      })
  },
})

export const {
  setTargetUrl,
  setActiveTab,
  setLastScanTime,
  setScanModalOpen,
  setIsScanning,
} = assessmentSlice.actions

export default assessmentSlice.reducer
