import { createSlice, createAsyncThunk } from '@reduxjs/toolkit'
import { adminApi, DashboardSummary } from '../../lib/adminApi'

export interface SummaryState {
  data: DashboardSummary | null
  loading: boolean
  error: string | null
  auditRunning: boolean
  auditError: string | null
}

const initialState: SummaryState = { data: null, loading: false, error: null, auditRunning: false, auditError: null }

export const fetchSummaryAsync = createAsyncThunk('summary/fetch', async (_, { rejectWithValue }) => {
  try {
    return await adminApi.summary()
  } catch (e: any) {
    return rejectWithValue(e.message || 'Backend unreachable')
  }
})

// Starts a real Lighthouse audit and polls until it finishes, then refreshes the summary.
export const runWebAuditAsync = createAsyncThunk('summary/runAudit', async (_, { dispatch, rejectWithValue }) => {
  try {
    await adminApi.webAuditRun()
  } catch (e: any) {
    if (!String(e.message).includes('409')) return rejectWithValue(e.message)
  }
  for (let i = 0; i < 90; i++) {
    await new Promise((r) => setTimeout(r, 3000))
    const st = await adminApi.webAuditStatus()
    if (!st.running) {
      await dispatch(fetchSummaryAsync())
      if (st.error) return rejectWithValue(st.error)
      return true
    }
  }
  return rejectWithValue('Web audit timed out')
})

const summarySlice = createSlice({
  name: 'summary',
  initialState,
  reducers: {},
  extraReducers: (b) => {
    b.addCase(fetchSummaryAsync.pending, (s) => { s.loading = true })
      .addCase(fetchSummaryAsync.fulfilled, (s, a) => { s.loading = false; s.data = a.payload; s.error = null })
      .addCase(fetchSummaryAsync.rejected, (s, a) => { s.loading = false; s.error = (a.payload as string) || 'Failed' })
      .addCase(runWebAuditAsync.pending, (s) => { s.auditRunning = true; s.auditError = null })
      .addCase(runWebAuditAsync.fulfilled, (s) => { s.auditRunning = false })
      .addCase(runWebAuditAsync.rejected, (s, a) => { s.auditRunning = false; s.auditError = (a.payload as string) || 'Audit failed' })
  },
})

export default summarySlice.reducer
