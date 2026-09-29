import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit'
import { Vulnerability, Severity, Status } from '../../types'
import { vulnerabilities as sampleVulns } from '../../data'
import {
  fetchFindings,
  mapBackendFinding,
  triageFinding,
  verifyFinding,
  rejectFinding,
} from '../../services/api'

export interface FindingsState {
  items: Vulnerability[]
  selectedFinding: Vulnerability | null
  severityFilter: Severity | 'All'
  statusFilter: Status | 'All'
  searchQuery: string
  isZeroData: boolean
  isLoading: boolean
  isLiveBackend: boolean
  error: string | null
}

const initialState: FindingsState = {
  items: sampleVulns,
  selectedFinding: null,
  severityFilter: 'All',
  statusFilter: 'All',
  searchQuery: '',
  isZeroData: false,
  isLoading: false,
  isLiveBackend: false,
  error: null,
}

// Background Thunks
export const fetchFindingsAsync = createAsyncThunk(
  'findings/fetchFindings',
  async (_, { rejectWithValue }) => {
    try {
      const res = await fetchFindings()
      if (res && res.findings && res.findings.length > 0) {
        return res.findings.map((f, i) => mapBackendFinding(f, i))
      }
      return []
    } catch (err: any) {
      return rejectWithValue(err.message || 'Failed to fetch findings')
    }
  }
)

export const triageFindingAsync = createAsyncThunk(
  'findings/triageFinding',
  async (
    { backendId, reason = 'Analyst marked in progress via dashboard' }: { id: number | string; backendId: string; reason?: string },
    { rejectWithValue }
  ) => {
    try {
      const ok = await triageFinding(backendId, reason)
      if (!ok) throw new Error('Triage failed on backend')
      return { backendId, reason }
    } catch (err: any) {
      return rejectWithValue(err.message)
    }
  }
)

export const verifyFindingAsync = createAsyncThunk(
  'findings/verifyFinding',
  async (
    { backendId, reason = 'Analyst verified remediation via dashboard', impact }: { id: number | string; backendId: string; reason?: string; impact?: string },
    { rejectWithValue }
  ) => {
    try {
      const ok = await verifyFinding(backendId, reason, impact)
      if (!ok) throw new Error('Verification failed on backend')
      return { backendId, reason }
    } catch (err: any) {
      return rejectWithValue(err.message)
    }
  }
)

export const rejectFindingAsync = createAsyncThunk(
  'findings/rejectFinding',
  async (
    { backendId, reason = 'Rejected by analyst as false positive' }: { id: number | string; backendId: string; reason?: string },
    { rejectWithValue }
  ) => {
    try {
      const ok = await rejectFinding(backendId, reason)
      if (!ok) throw new Error('Rejection failed on backend')
      return { backendId, reason }
    } catch (err: any) {
      return rejectWithValue(err.message)
    }
  }
)

export const findingsSlice = createSlice({
  name: 'findings',
  initialState,
  reducers: {
    setFindings: (state, action: PayloadAction<Vulnerability[]>) => {
      state.items = action.payload
    },
    // 0ms Optimistic UI status transition
    updateStatusOptimistic: (
      state,
      action: PayloadAction<{ id: number | string; status: Status }>
    ) => {
      const { id, status } = action.payload
      const item = state.items.find((v) => v.id === id)
      if (item) {
        item.status = status
      }
      if (state.selectedFinding && state.selectedFinding.id === id) {
        state.selectedFinding.status = status
      }
    },
    setSelectedFinding: (state, action: PayloadAction<Vulnerability | null>) => {
      state.selectedFinding = action.payload
    },
    setSeverityFilter: (state, action: PayloadAction<Severity | 'All'>) => {
      state.severityFilter = action.payload
    },
    setStatusFilter: (state, action: PayloadAction<Status | 'All'>) => {
      state.statusFilter = action.payload
    },
    setSearchQuery: (state, action: PayloadAction<string>) => {
      state.searchQuery = action.payload
    },
    toggleZeroData: (state) => {
      state.isZeroData = !state.isZeroData
    },
    setZeroData: (state, action: PayloadAction<boolean>) => {
      state.isZeroData = action.payload
    },
  },
  extraReducers: (builder) => {
    builder
      // Fetch Findings
      .addCase(fetchFindingsAsync.pending, (state) => {
        state.isLoading = true
        state.error = null
      })
      .addCase(fetchFindingsAsync.fulfilled, (state, action) => {
        state.isLoading = false
        if (action.payload.length > 0) {
          state.items = action.payload
          state.isLiveBackend = true
        } else {
          state.isLiveBackend = false
        }
      })
      .addCase(fetchFindingsAsync.rejected, (state, action) => {
        state.isLoading = false
        state.error = (action.payload as string) || 'Error fetching findings'
        state.isLiveBackend = false
      })
  },
})

export const {
  setFindings,
  updateStatusOptimistic,
  setSelectedFinding,
  setSeverityFilter,
  setStatusFilter,
  setSearchQuery,
  toggleZeroData,
  setZeroData,
} = findingsSlice.actions

export default findingsSlice.reducer
