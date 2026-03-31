import { describe, test, expect } from "bun:test"
import { ConversationContext } from "../src/llm/context.js"

describe("ConversationContext", () => {
  const baseOpts = {
    systemPrompt: "You are a security evaluator.",
    accumulate: false,
    detectionsOnly: true,
    maxPairs: 5,
    maxChars: 16000,
  }

  describe("stateless mode (accumulate=false)", () => {
    test("getMessages returns system prompt + current user message", () => {
      const ctx = new ConversationContext(baseOpts)
      ctx.addUserMessage("evaluate this command")
      const msgs = ctx.getMessages()
      expect(msgs).toHaveLength(2)
      expect(msgs[0]).toEqual({ role: "system", content: "You are a security evaluator." })
      expect(msgs[1]).toEqual({ role: "user", content: "evaluate this command" })
    })

    test("getMessages returns only system prompt when no user message", () => {
      const ctx = new ConversationContext(baseOpts)
      const msgs = ctx.getMessages()
      expect(msgs).toHaveLength(1)
      expect(msgs[0].role).toBe("system")
    })

    test("addAssistantMessage does not retain history", () => {
      const ctx = new ConversationContext(baseOpts)
      ctx.addUserMessage("first prompt")
      ctx.addAssistantMessage("first response", true)

      ctx.addUserMessage("second prompt")
      const msgs = ctx.getMessages()
      expect(msgs).toHaveLength(2) // system + current user only
      expect(msgs[1].content).toBe("second prompt")
    })

    test("addAssistantMessage clears pending user message", () => {
      const ctx = new ConversationContext(baseOpts)
      ctx.addUserMessage("a prompt")
      ctx.addAssistantMessage("a response")
      const msgs = ctx.getMessages()
      expect(msgs).toHaveLength(1) // system only
    })
  })

  describe("accumulation mode", () => {
    test("detectionsOnly=true keeps only pairs with detections", () => {
      const ctx = new ConversationContext({
        ...baseOpts,
        accumulate: true,
        detectionsOnly: true,
      })

      ctx.addUserMessage("safe command")
      ctx.addAssistantMessage("safe response", false) // not kept

      ctx.addUserMessage("dangerous command")
      ctx.addAssistantMessage("danger response", true) // kept

      ctx.addUserMessage("current query")
      const msgs = ctx.getMessages()

      // system + 1 history pair (2 msgs) + current user
      expect(msgs).toHaveLength(4)
      expect(msgs[1].content).toBe("dangerous command")
      expect(msgs[2].content).toBe("danger response")
      expect(msgs[3].content).toBe("current query")
    })

    test("detectionsOnly=false keeps all pairs", () => {
      const ctx = new ConversationContext({
        ...baseOpts,
        accumulate: true,
        detectionsOnly: false,
      })

      ctx.addUserMessage("first command")
      ctx.addAssistantMessage("first response", false)

      ctx.addUserMessage("second command")
      ctx.addAssistantMessage("second response", false)

      ctx.addUserMessage("current")
      const msgs = ctx.getMessages()

      // system + 2 history pairs (4 msgs) + current user
      expect(msgs).toHaveLength(6)
    })

    test("maxPairs limits retained history (oldest dropped)", () => {
      const ctx = new ConversationContext({
        ...baseOpts,
        accumulate: true,
        detectionsOnly: false,
        maxPairs: 2,
      })

      ctx.addUserMessage("first")
      ctx.addAssistantMessage("r1", false)
      ctx.addUserMessage("second")
      ctx.addAssistantMessage("r2", false)
      ctx.addUserMessage("third")
      ctx.addAssistantMessage("r3", false)

      ctx.addUserMessage("current")
      const msgs = ctx.getMessages()

      // system + 2 pairs (4 msgs) + current
      expect(msgs).toHaveLength(6)
      // Oldest pair ("first"/"r1") should be dropped
      expect(msgs[1].content).toBe("second")
      expect(msgs[3].content).toBe("third")
    })

    test("maxChars enforces sliding window (oldest dropped)", () => {
      const ctx = new ConversationContext({
        ...baseOpts,
        accumulate: true,
        detectionsOnly: false,
        maxPairs: 100,
        maxChars: 50, // very small
      })

      // Each pair is ~40 chars → second pair pushes over limit
      ctx.addUserMessage("aaaaaaaaaaaaaaaaaaa") // 19 chars
      ctx.addAssistantMessage("bbbbbbbbbbbbbbbbbbb", false) // 19 chars → 38 total

      ctx.addUserMessage("ccccccccccccccccccc") // 19 chars
      ctx.addAssistantMessage("ddddddddddddddddddd", false) // 19 chars → would be 76

      // After trim, oldest pair should be dropped since 76 > 50
      ctx.addUserMessage("current")
      const msgs = ctx.getMessages()

      // Should have dropped first pair
      expect(msgs[1].content).toBe("ccccccccccccccccccc")
    })
  })

  describe("reset", () => {
    test("reset clears history and pending message", () => {
      const ctx = new ConversationContext({
        ...baseOpts,
        accumulate: true,
        detectionsOnly: false,
      })

      ctx.addUserMessage("q1")
      ctx.addAssistantMessage("a1", false)
      ctx.addUserMessage("q2")

      ctx.reset()
      const msgs = ctx.getMessages()
      expect(msgs).toHaveLength(1) // system only
    })
  })
})
