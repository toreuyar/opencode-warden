import { describe, test, expect } from "bun:test"
import { buildLlmHeaders } from "../src/llm/client.js"

describe("buildLlmHeaders", () => {
  test("sets Content-Type by default", () => {
    const headers = buildLlmHeaders("", {})
    expect(headers["Content-Type"]).toBe("application/json")
  })

  test("sets Bearer auth when apiKey is provided", () => {
    const headers = buildLlmHeaders("my-key", {})
    expect(headers["Authorization"]).toBe("Bearer my-key")
  })

  test("does not set Authorization when apiKey is empty", () => {
    const headers = buildLlmHeaders("", {})
    expect(headers["Authorization"]).toBeUndefined()
  })

  test("custom headers are merged", () => {
    const headers = buildLlmHeaders("", {
      "X-Custom": "value",
      "X-Client-ID": "warden",
    })
    expect(headers["X-Custom"]).toBe("value")
    expect(headers["X-Client-ID"]).toBe("warden")
    expect(headers["Content-Type"]).toBe("application/json")
  })

  test("custom headers override auto-generated headers", () => {
    const headers = buildLlmHeaders("my-key", {
      Authorization: "Token internal-token",
    })
    // Custom Authorization overrides the Bearer auth
    expect(headers["Authorization"]).toBe("Token internal-token")
  })

  test("custom headers override Content-Type", () => {
    const headers = buildLlmHeaders("", {
      "Content-Type": "text/plain",
    })
    expect(headers["Content-Type"]).toBe("text/plain")
  })

  test("full merge order: Content-Type → Bearer → custom", () => {
    const headers = buildLlmHeaders("my-key", {
      "api-key": "azure-key",
    })
    expect(headers["Content-Type"]).toBe("application/json")
    expect(headers["Authorization"]).toBe("Bearer my-key")
    expect(headers["api-key"]).toBe("azure-key")
  })
})
