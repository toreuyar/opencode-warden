import type { LlmMessage } from "../types.js"

export interface ConversationContextOptions {
  systemPrompt: string
  /** Whether to keep previous exchanges in context. Default: false (stateless). */
  accumulate: boolean
  /** When true, only exchanges with detections are kept. Default: true. */
  detectionsOnly: boolean
  /** Maximum number of user+assistant pairs to retain. Default: 5. */
  maxPairs: number
  /** Maximum total characters across all history messages. Oldest pairs are
   *  dropped when this limit is exceeded (sliding window). Default: 16000. */
  maxChars: number
}

interface MessagePair {
  user: LlmMessage
  assistant: LlmMessage
  hadDetection: boolean
}

export class ConversationContext {
  private systemPrompt: string
  private accumulate: boolean
  private detectionsOnly: boolean
  private maxPairs: number
  private maxChars: number
  private history: MessagePair[] = []
  private pendingUserMessage: LlmMessage | null = null

  constructor(options: ConversationContextOptions) {
    this.systemPrompt = options.systemPrompt
    this.accumulate = options.accumulate
    this.detectionsOnly = options.detectionsOnly
    this.maxPairs = options.maxPairs
    this.maxChars = options.maxChars
  }

  addUserMessage(content: string): void {
    this.pendingUserMessage = { role: "user", content }
  }

  /**
   * Record the assistant response. When accumulation is enabled, the
   * user+assistant pair may be kept in history based on detectionsOnly
   * and sliding window limits.
   */
  addAssistantMessage(content: string, hadDetection: boolean = false): void {
    if (this.accumulate && this.pendingUserMessage) {
      const shouldKeep = this.detectionsOnly ? hadDetection : true
      if (shouldKeep) {
        this.history.push({
          user: this.pendingUserMessage,
          assistant: { role: "assistant", content },
          hadDetection,
        })
        this.trim()
      }
    }
    this.pendingUserMessage = null
  }

  /**
   * Build the message array for the current LLM call.
   * Always: system prompt + history pairs + current user message.
   */
  getMessages(): LlmMessage[] {
    const messages: LlmMessage[] = [
      { role: "system", content: this.systemPrompt },
    ]
    for (const pair of this.history) {
      messages.push(pair.user, pair.assistant)
    }
    if (this.pendingUserMessage) {
      messages.push(this.pendingUserMessage)
    }
    return messages
  }

  reset(): void {
    this.history = []
    this.pendingUserMessage = null
  }

  private trim(): void {
    // Enforce max pairs limit — drop oldest first
    while (this.history.length > this.maxPairs) {
      this.history.shift()
    }

    // Enforce max chars limit — drop oldest pairs until under budget
    while (this.history.length > 0 && this.totalChars() > this.maxChars) {
      this.history.shift()
    }
  }

  private totalChars(): number {
    let total = 0
    for (const pair of this.history) {
      total += pair.user.content.length + pair.assistant.content.length
    }
    return total
  }
}
