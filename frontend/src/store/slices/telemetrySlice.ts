import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit'
import {
  fetchRadarData,
  fetchAttackSurface,
  fetchNetworkInspect,
  probeNetworkEndpoint,
  TelemetryAttackSurfaceNode,
  NetworkInspectResponse,
} from '../../services/api'
import { RadarDataPoint } from '../../types'
import { radarData as defaultRadar } from '../../data'

export interface TelemetryState {
  radar: RadarDataPoint[]
  attackSurfaceNodes: Record<string, TelemetryAttackSurfaceNode>
  networkInspect: NetworkInspectResponse | null
  isLoading: boolean
  error: string | null
}

const initialState: TelemetryState = {
  radar: defaultRadar,
  attackSurfaceNodes: {},
  networkInspect: null,
  isLoading: false,
  error: null,
}

export const fetchRadarAsync = createAsyncThunk(
  'telemetry/fetchRadar',
  async (_, { rejectWithValue }) => {
    try {
      const data = await fetchRadarData()
      return data
    } catch (err: any) {
      return rejectWithValue(err.message)
    }
  }
)

export const fetchAttackSurfaceAsync = createAsyncThunk(
  'telemetry/fetchAttackSurface',
  async (_, { rejectWithValue }) => {
    try {
      const nodes = await fetchAttackSurface()
      return nodes
    } catch (err: any) {
      return rejectWithValue(err.message)
    }
  }
)

export const fetchNetworkInspectAsync = createAsyncThunk(
  'telemetry/fetchNetworkInspect',
  async (targetUrl: string | undefined, { rejectWithValue }) => {
    try {
      const data = await fetchNetworkInspect(targetUrl)
      return data
    } catch (err: any) {
      return rejectWithValue(err.message)
    }
  }
)

export const probeEndpointAsync = createAsyncThunk(
  'telemetry/probeEndpoint',
  async (urlOrPath: string, { rejectWithValue }) => {
    try {
      const res = await probeNetworkEndpoint(urlOrPath)
      return res
    } catch (err: any) {
      return rejectWithValue(err.message)
    }
  }
)

export const telemetrySlice = createSlice({
  name: 'telemetry',
  initialState,
  reducers: {
    setRadar: (state, action: PayloadAction<RadarDataPoint[]>) => {
      state.radar = action.payload
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchRadarAsync.fulfilled, (state, action) => {
        if (action.payload && action.payload.length > 0) {
          state.radar = action.payload
        }
      })
      .addCase(fetchAttackSurfaceAsync.fulfilled, (state, action) => {
        if (action.payload && action.payload.length > 0) {
          const map: Record<string, TelemetryAttackSurfaceNode> = {}
          action.payload.forEach((n) => {
            map[n.id] = n
          })
          state.attackSurfaceNodes = map
        }
      })
      .addCase(fetchNetworkInspectAsync.fulfilled, (state, action) => {
        if (action.payload) {
          state.networkInspect = action.payload
        }
      })
  },
})

export const { setRadar } = telemetrySlice.actions

export default telemetrySlice.reducer
