import { configureStore } from '@reduxjs/toolkit'
import { TypedUseSelectorHook, useDispatch, useSelector } from 'react-redux'
import findingsReducer from './slices/findingsSlice'
import assessmentReducer from './slices/assessmentSlice'
import devtoolsReducer from './slices/devtoolsSlice'
import copilotReducer from './slices/copilotSlice'
import telemetryReducer from './slices/telemetrySlice'

export const store = configureStore({
  reducer: {
    findings: findingsReducer,
    assessment: assessmentReducer,
    devtools: devtoolsReducer,
    copilot: copilotReducer,
    telemetry: telemetryReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: false,
    }),
})

export type RootState = ReturnType<typeof store.getState>
export type AppDispatch = typeof store.dispatch

// Custom typed hooks for high-performance usage
export const useAppDispatch = () => useDispatch<AppDispatch>()
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector
