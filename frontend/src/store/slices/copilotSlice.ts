import { createSlice, createAsyncThunk, PayloadAction } from '@reduxjs/toolkit'
import {
  askCopilot,
  fetchCopilotRecommendations,
  CopilotRecommendation,
  CopilotChatResponse,
} from '../../services/api'

export interface CopilotMessage {
  sender: 'user' | 'ai'
  text: string
  code?: string
  timestamp?: string
}

export interface CopilotState {
  messages: CopilotMessage[]
  recommendations: CopilotRecommendation[]
  isTyping: boolean
  error: string | null
}

const initialState: CopilotState = {
  messages: [],
  recommendations: [],
  isTyping: false,
  error: null,
}

export const fetchRecommendationsAsync = createAsyncThunk(
  'copilot/fetchRecommendations',
  async (_, { rejectWithValue }) => {
    try {
      const recs = await fetchCopilotRecommendations()
      return recs
    } catch (err: any) {
      return rejectWithValue(err.message)
    }
  }
)

// Answers come from the backend (Groq, grounded in stored findings). If it is unreachable we say so:
// no canned or simulated answers are ever shown.
export const askCopilotAsync = createAsyncThunk(
  'copilot/askCopilot',
  async ({ prompt, findingId }: { prompt: string; findingId?: string }) => {
    const res = await askCopilot(prompt, findingId)
    if (res && res.reply) return res
    const unavailable: CopilotChatResponse = {
      reply: 'The assessment backend did not answer. Start it with `make server` and try again.',
      codeSnippet: undefined,
      model: 'unavailable',
      timestamp: new Date().toISOString(),
    }
    return unavailable
  }
)

export const copilotSlice = createSlice({
  name: 'copilot',
  initialState,
  reducers: {
    // 0ms Optimistic user message dispatch
    addUserMessageOptimistic: (state, action: PayloadAction<string>) => {
      state.messages.push({
        sender: 'user',
        text: action.payload,
        timestamp: new Date().toLocaleTimeString(),
      })
      state.isTyping = true
    },
    clearMessages: (state) => {
      state.messages = []
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchRecommendationsAsync.fulfilled, (state, action) => {
        state.recommendations = action.payload || []
      })
      .addCase(askCopilotAsync.fulfilled, (state, action) => {
        state.isTyping = false
        state.messages.push({
          sender: 'ai',
          text: action.payload.reply,
          code: action.payload.codeSnippet || undefined,
          timestamp: new Date().toLocaleTimeString(),
        })
      })
      .addCase(askCopilotAsync.rejected, (state, action) => {
        state.isTyping = false
        state.error = (action.payload as string) || 'Failed to query copilot'
      })
  },
})

export const { addUserMessageOptimistic, clearMessages } = copilotSlice.actions

export default copilotSlice.reducer
