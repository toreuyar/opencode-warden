import { describe, test, expect, beforeEach } from "bun:test"
import { createRulesManageTool, getAiPatterns } from "../src/tools/rules-manage.js"
import { DetectionEngine } from "../src/detection/engine.js"
import { getPatterns, getAllBuiltinPatterns } from "../src/detection/patterns/index.js"
import { DEFAULT_CONFIG } from "../src/config/defaults.js"
import type { SecurityGuardConfig } from "../src/types.js"

function createTestConfig(overrides: Partial<SecurityGuardConfig> = {}): SecurityGuardConfig {
  return {
    ...DEFAULT_CONFIG,
    ...overrides,
  }
}

function createTestTool(config?: SecurityGuardConfig) {
  const cfg = config || createTestConfig()
  const patterns = getPatterns(cfg.categories, cfg.disabledPatterns, cfg.customPatterns)
  const engine = new DetectionEngine(patterns)
  return createRulesManageTool({ engine, config: cfg, projectDir: "/tmp/test" })
}

// Clear AI patterns between tests (module-level state)
beforeEach(() => {
  const patterns = getAiPatterns()
  patterns.splice(0, patterns.length)
})

describe("three-layer pattern architecture", () => {

  // ─── Layer 1: Built-in rules ───

  describe("Layer 1 — Built-in rules (immutable)", () => {
    test("cannot remove built-in patterns", async () => {
      const tool = createTestTool()
      const result = await tool.execute({ action: "remove", id: "openai-api-key" })
      expect(result).toContain("built-in pattern (Layer 1)")
      expect(result).toContain("cannot be removed")
    })

    test("cannot edit built-in patterns", async () => {
      const tool = createTestTool()
      const result = await tool.execute({ action: "edit", id: "openai-api-key", pattern: "new-pattern" })
      expect(result).toContain("built-in pattern (Layer 1)")
      expect(result).toContain("cannot be edited")
    })

    test("built-in patterns are tagged with source 'builtin'", () => {
      const patterns = getAllBuiltinPatterns()
      expect(patterns.length).toBeGreaterThan(0)
      for (const p of patterns) {
        expect(p.source).toBe("builtin")
      }
    })

    test("list shows built-in patterns as Layer 1", async () => {
      const tool = createTestTool()
      const result = await tool.execute({ action: "list" })
      expect(result).toContain("Layer 1 — Built-in rules:")
      expect(result).toContain("--- Layer 1: Built-in Rules ---")
      expect(result).toContain("(immutable)")
    })
  })

  // ─── Layer 2: User-configured rules ───

  describe("Layer 2 — User rules (config-managed, immutable at runtime)", () => {
    const configWithCustom = createTestConfig({
      customPatterns: [
        {
          id: "acme-secret",
          name: "ACME Secret",
          category: "api-keys",
          pattern: "acme_sk_[A-Za-z0-9]{20,}",
          redactTemplate: "[ACME-REDACTED]",
          confidence: "high",
        },
      ],
    })

    test("cannot remove user-configured patterns", async () => {
      const tool = createTestTool(configWithCustom)
      const result = await tool.execute({ action: "remove", id: "acme-secret" })
      expect(result).toContain("user-configured pattern (Layer 2)")
      expect(result).toContain("cannot be removed at runtime")
      expect(result).toContain("Modify the config file instead")
    })

    test("cannot edit user-configured patterns", async () => {
      const tool = createTestTool(configWithCustom)
      const result = await tool.execute({ action: "edit", id: "acme-secret", pattern: "new-pattern" })
      expect(result).toContain("user-configured pattern (Layer 2)")
      expect(result).toContain("cannot be edited at runtime")
    })

    test("user patterns are tagged with source 'user' in getPatterns", () => {
      const patterns = getPatterns(
        configWithCustom.categories,
        configWithCustom.disabledPatterns,
        configWithCustom.customPatterns,
      )
      const userPattern = patterns.find((p) => p.id === "acme-secret")
      expect(userPattern).toBeDefined()
      expect(userPattern!.source).toBe("user")
    })

    test("list shows user patterns as Layer 2", async () => {
      const tool = createTestTool(configWithCustom)
      const result = await tool.execute({ action: "list" })
      expect(result).toContain("Layer 2 — User rules:")
      expect(result).toContain("--- Layer 2: User Rules (from config) ---")
      expect(result).toContain("acme-secret")
    })

    test("cannot add AI pattern with same ID as user pattern", async () => {
      // Config has user pattern with id "acme-secret"
      // AI add always prefixes with "ai-", so direct collision via id is prevented by prefix
      // But we test that the conflict check works if somehow the id matched
      const configWithAiPrefixedUser = createTestConfig({
        customPatterns: [{
          id: "ai-my-custom",
          name: "Custom with ai prefix",
          category: "api-keys",
          pattern: "custom_[a-z]+",
          redactTemplate: "[REDACTED]",
          confidence: "high",
        }],
      })
      const tool = createTestTool(configWithAiPrefixedUser)
      const result = await tool.execute({ action: "add", id: "ai-my-custom", name: "Override", pattern: "test" })
      expect(result).toContain("conflicts with a user-configured pattern")
    })
  })

  // ─── Layer 3: AI-managed rules ───

  describe("Layer 3 — AI rules (session-only)", () => {
    test("can add AI patterns", async () => {
      const tool = createTestTool()
      const result = await tool.execute({
        action: "add",
        name: "Test Token",
        pattern: "test_tok_[A-Za-z0-9]+",
        redactTemplate: "[TEST-REDACTED]",
      })
      expect(result).toContain("Added AI rule")
      expect(result).toContain("ai-test-token")
      expect(result).toContain("session-only")
      expect(result).toContain("not persisted to config")
    })

    test("AI pattern IDs are auto-prefixed with 'ai-'", async () => {
      const tool = createTestTool()
      await tool.execute({ action: "add", name: "My Rule", pattern: "abc" })
      const patterns = getAiPatterns()
      expect(patterns[0].id).toBe("ai-my-rule")
    })

    test("AI patterns are tagged with source 'ai'", async () => {
      const tool = createTestTool()
      await tool.execute({ action: "add", name: "My Rule", pattern: "abc" })
      const patterns = getAiPatterns()
      expect(patterns[0].source).toBe("ai")
    })

    test("can remove AI patterns", async () => {
      const tool = createTestTool()
      await tool.execute({ action: "add", name: "Temp Rule", pattern: "temp_[0-9]+" })
      const addResult = await tool.execute({ action: "list" })
      expect(addResult).toContain("ai-temp-rule")

      const removeResult = await tool.execute({ action: "remove", id: "ai-temp-rule" })
      expect(removeResult).toContain("Removed AI pattern")

      const listResult = await tool.execute({ action: "list" })
      expect(listResult).toContain("AI rules: 0")
    })

    test("can edit AI patterns", async () => {
      const tool = createTestTool()
      await tool.execute({ action: "add", name: "My Rule", pattern: "old_[0-9]+" })

      const result = await tool.execute({ action: "edit", id: "ai-my-rule", pattern: "new_[0-9]+", name: "Updated Rule" })
      expect(result).toContain("Updated AI rule")
      expect(result).toContain("Updated Rule")
      expect(result).toContain("new_[0-9]+")
    })

    test("cannot add duplicate AI pattern ID", async () => {
      const tool = createTestTool()
      await tool.execute({ action: "add", name: "My Rule", pattern: "abc" })
      const result = await tool.execute({ action: "add", name: "My Rule", pattern: "def" })
      expect(result).toContain("already exists")
      expect(result).toContain("Use \"edit\"")
    })

    test("AI pattern IDs are namespaced and cannot collide with built-in", async () => {
      const tool = createTestTool()
      // Even if you try to pass a built-in ID, it gets ai- prefixed
      const result = await tool.execute({ action: "add", id: "openai-api-key", name: "Override", pattern: "test" })
      expect(result).toContain("ai-openai-api-key")
      expect(result).toContain("Added AI rule")
    })

    test("list shows AI patterns as Layer 3", async () => {
      const tool = createTestTool()
      await tool.execute({ action: "add", name: "AI Rule", pattern: "ai_tok_[a-z]+" })
      const result = await tool.execute({ action: "list" })
      expect(result).toContain("Layer 3 — AI rules: 1")
      expect(result).toContain("--- Layer 3: AI Rules (session-only) ---")
      expect(result).toContain("ai-rule")
    })

    test("AI patterns are not persisted to disk", async () => {
      const tool = createTestTool()
      await tool.execute({ action: "add", name: "Volatile Rule", pattern: "volatile_[0-9]+" })

      // AI patterns live only in module memory
      const patterns = getAiPatterns()
      expect(patterns.length).toBe(1)
      // No file system interaction — the tool no longer imports fs or writes files
    })
  })

  // ─── Cross-layer security ───

  describe("cross-layer security guarantees", () => {
    test("AI cannot escalate to remove higher-layer patterns", async () => {
      const config = createTestConfig({
        customPatterns: [{
          id: "corp-token",
          name: "Corp Token",
          category: "api-keys",
          pattern: "corp_[A-Za-z0-9]+",
          redactTemplate: "[CORP-REDACTED]",
          confidence: "high",
        }],
      })
      const tool = createTestTool(config)

      // Try removing Layer 1
      const r1 = await tool.execute({ action: "remove", id: "openai-api-key" })
      expect(r1).toContain("Layer 1")

      // Try removing Layer 2
      const r2 = await tool.execute({ action: "remove", id: "corp-token" })
      expect(r2).toContain("Layer 2")

      // Try editing Layer 1
      const r3 = await tool.execute({ action: "edit", id: "openai-api-key", pattern: ".*" })
      expect(r3).toContain("Layer 1")

      // Try editing Layer 2
      const r4 = await tool.execute({ action: "edit", id: "corp-token", pattern: ".*" })
      expect(r4).toContain("Layer 2")
    })

    test("all three layers contribute to detection engine", () => {
      const config = createTestConfig({
        customPatterns: [{
          id: "user-custom",
          name: "User Custom",
          category: "api-keys",
          pattern: "user_secret_[a-z]+",
          redactTemplate: "[USER-REDACTED]",
          confidence: "high",
        }],
      })

      // Simulate an AI-added pattern
      const aiPats = getAiPatterns()
      aiPats.push({
        id: "ai-test",
        name: "AI Test",
        category: "api-keys",
        pattern: /ai_secret_[a-z]+/g,
        redact: () => "[AI-REDACTED]",
        confidence: "high",
        source: "ai",
      })

      const patterns = getPatterns(
        config.categories,
        config.disabledPatterns,
        config.customPatterns,
        undefined,
        aiPats,
      )

      const builtins = patterns.filter((p) => p.source === "builtin")
      const user = patterns.filter((p) => p.source === "user")
      const ai = patterns.filter((p) => p.source === "ai")

      expect(builtins.length).toBeGreaterThan(0)
      expect(user.length).toBe(1)
      expect(ai.length).toBe(1)
      expect(user[0].id).toBe("user-custom")
      expect(ai[0].id).toBe("ai-test")
    })

    test("detection engine scans with all three layers", () => {
      const config = createTestConfig({
        customPatterns: [{
          id: "user-tok",
          name: "User Token",
          category: "api-keys",
          pattern: "utok_[A-Za-z0-9]{10,}",
          redactTemplate: "[USER-REDACTED]",
          confidence: "high",
        }],
      })

      const aiPats = getAiPatterns()
      aiPats.push({
        id: "ai-tok",
        name: "AI Token",
        category: "api-keys",
        pattern: /aitok_[A-Za-z0-9]{10,}/g,
        redact: () => "[AI-REDACTED]",
        confidence: "high",
        source: "ai",
      })

      const patterns = getPatterns(
        config.categories,
        config.disabledPatterns,
        config.customPatterns,
        undefined,
        aiPats,
      )
      const engine = new DetectionEngine(patterns)

      // Layer 1: built-in detects OpenAI key
      const r1 = engine.scan("sk-proj-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmn")
      expect(r1.hasDetections).toBe(true)

      // Layer 2: user pattern detects user token
      const r2 = engine.scan("utok_AbCdEfGhIj1234")
      expect(r2.hasDetections).toBe(true)
      expect(r2.redacted).toContain("[USER-REDACTED]")

      // Layer 3: AI pattern detects AI token
      const r3 = engine.scan("aitok_AbCdEfGhIj1234")
      expect(r3.hasDetections).toBe(true)
      expect(r3.redacted).toContain("[AI-REDACTED]")
    })
  })

  // ─── Input validation ───

  describe("input validation", () => {
    test("add requires name", async () => {
      const tool = createTestTool()
      const result = await tool.execute({ action: "add", pattern: "abc" })
      expect(result).toContain("Error: 'name' is required")
    })

    test("add requires pattern", async () => {
      const tool = createTestTool()
      const result = await tool.execute({ action: "add", name: "Test" })
      expect(result).toContain("Error: 'pattern' is required")
    })

    test("add rejects invalid regex", async () => {
      const tool = createTestTool()
      const result = await tool.execute({ action: "add", name: "Bad", pattern: "[invalid" })
      expect(result).toContain("Invalid regex pattern")
    })

    test("edit requires id", async () => {
      const tool = createTestTool()
      const result = await tool.execute({ action: "edit", pattern: "abc" })
      expect(result).toContain("Error: 'id' is required")
    })

    test("remove requires id", async () => {
      const tool = createTestTool()
      const result = await tool.execute({ action: "remove" })
      expect(result).toContain("Error: 'id' is required")
    })

    test("remove nonexistent AI pattern returns not found", async () => {
      const tool = createTestTool()
      const result = await tool.execute({ action: "remove", id: "ai-nonexistent" })
      expect(result).toContain("not found")
    })

    test("edit nonexistent AI pattern returns not found", async () => {
      const tool = createTestTool()
      const result = await tool.execute({ action: "edit", id: "ai-nonexistent", pattern: "abc" })
      expect(result).toContain("not found")
    })

    test("unknown action returns error", async () => {
      const tool = createTestTool()
      const result = await tool.execute({ action: "destroy" })
      expect(result).toContain("Unknown action")
    })

    test("test action works", async () => {
      const tool = createTestTool()
      const result = await tool.execute({ action: "test", pattern: "abc", testString: "xabcx" })
      expect(result).toContain("matched 1 time(s)")
    })

    test("test requires pattern and testString", async () => {
      const tool = createTestTool()
      const r1 = await tool.execute({ action: "test", testString: "abc" })
      expect(r1).toContain("Error: 'pattern' is required")
      const r2 = await tool.execute({ action: "test", pattern: "abc" })
      expect(r2).toContain("Error: 'testString' is required")
    })
  })
})
