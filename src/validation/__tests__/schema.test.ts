import { describe, it, expect } from "vitest";
import { SchemaValidator } from "../index.js";
import type { ToolOutputSchema, SchemaValidationConfig } from "../../types/validation.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function createValidator(overrides?: Partial<SchemaValidationConfig>): SchemaValidator {
  return new SchemaValidator({ enabled: true, ...overrides });
}

// ---------------------------------------------------------------------------
// Tests 27–36
// ---------------------------------------------------------------------------

describe("SchemaValidator", () => {
  // 27. No schema registered, strict default → bare string fails, object passes
  it("27. strict default: bare string fails, object passes", () => {
    const v = createValidator({ defaultBehavior: "strict" });

    const strResult = v.validate("hello", "srv", "tool");
    expect(strResult.pass).toBe(false);
    expect(strResult.ruleIds).toContain("schema.type-mismatch");

    const objResult = v.validate({ foo: "bar" }, "srv", "tool");
    expect(objResult.pass).toBe(true);

    const arrResult = v.validate([1, 2], "srv", "tool");
    expect(arrResult.pass).toBe(true);
  });

  // 28. No schema registered, lenient default → bare string passes
  it("28. lenient default: bare string passes", () => {
    const v = createValidator({ defaultBehavior: "lenient" });

    const result = v.validate("hello", "srv", "tool");
    expect(result.pass).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  // 29. Schema with discriminant → correct variant selected and validated
  it("29. discriminant selects correct variant", () => {
    const schema: ToolOutputSchema = {
      discriminant: "type",
      variants: {
        success: {
          required: ["data"],
          fields: { data: "string" },
        },
        error: {
          required: ["message"],
          fields: { message: "string" },
        },
      },
    };
    const v = createValidator({ toolSchemas: { "srv:tool": schema } });

    const okResult = v.validate({ type: "success", data: "hi" }, "srv", "tool");
    expect(okResult.pass).toBe(true);

    const errResult = v.validate({ type: "error", message: "fail" }, "srv", "tool");
    expect(errResult.pass).toBe(true);
  });

  // 30. Schema with discriminant → unknown discriminant value fails
  it("30. unknown discriminant value fails", () => {
    const schema: ToolOutputSchema = {
      discriminant: "type",
      variants: {
        success: { required: ["data"] },
      },
    };
    const v = createValidator({ toolSchemas: { "srv:tool": schema } });

    const result = v.validate({ type: "unknown" }, "srv", "tool");
    expect(result.pass).toBe(false);
    expect(result.ruleIds).toContain("schema.type-mismatch");
    expect(result.violations[0]).toContain("unknown");
  });

  // 31. Required field missing → fail with schema.missing-field
  it("31. missing required field", () => {
    const schema: ToolOutputSchema = {
      variants: {
        default: {
          required: ["name", "age"],
          fields: { name: "string", age: "number" },
        },
      },
    };
    const v = createValidator({ toolSchemas: { "srv:tool": schema } });

    const result = v.validate({ name: "Alice" }, "srv", "tool");
    expect(result.pass).toBe(false);
    expect(result.ruleIds).toContain("schema.missing-field");
    expect(result.violations.some((v) => v.includes('"age"'))).toBe(true);
  });

  // 32. Field type mismatch → fail with schema.type-mismatch
  it("32. field type mismatch", () => {
    const schema: ToolOutputSchema = {
      variants: {
        default: {
          required: ["count"],
          fields: { count: "number" },
        },
      },
    };
    const v = createValidator({ toolSchemas: { "srv:tool": schema } });

    const result = v.validate({ count: "five" }, "srv", "tool");
    expect(result.pass).toBe(false);
    expect(result.ruleIds).toContain("schema.type-mismatch");
  });

  // 33. Extra field, allowExtra=false → fail with schema.extra-field
  it("33. extra field with allowExtra=false", () => {
    const schema: ToolOutputSchema = {
      variants: {
        default: {
          required: ["id"],
          fields: { id: "number" },
          allowExtra: false,
        },
      },
    };
    const v = createValidator({ toolSchemas: { "srv:tool": schema } });

    const result = v.validate({ id: 1, secret: "oops" }, "srv", "tool");
    expect(result.pass).toBe(false);
    expect(result.ruleIds).toContain("schema.extra-field");
    expect(result.violations.some((v) => v.includes('"secret"'))).toBe(true);
  });

  // 34. Extra field, allowExtra=true → pass
  it("34. extra field with allowExtra=true passes", () => {
    const schema: ToolOutputSchema = {
      variants: {
        default: {
          required: ["id"],
          fields: { id: "number" },
          allowExtra: true,
        },
      },
    };
    const v = createValidator({ toolSchemas: { "srv:tool": schema } });

    const result = v.validate({ id: 1, extra: "fine" }, "srv", "tool");
    expect(result.pass).toBe(true);
  });

  // 35. Schema disabled → always passes
  it("35. disabled validator always passes", () => {
    const v = new SchemaValidator({ enabled: false, toolSchemas: {}, defaultBehavior: "strict" });

    const result = v.validate("anything", "srv", "tool");
    expect(result.pass).toBe(true);
    expect(result.violations).toHaveLength(0);
  });

  // 36. Multiple violations → all reported
  it("36. multiple violations all reported", () => {
    const schema: ToolOutputSchema = {
      variants: {
        default: {
          required: ["a", "b"],
          fields: { a: "string", b: "number", c: "boolean" },
          allowExtra: false,
        },
      },
    };
    const v = createValidator({ toolSchemas: { "srv:tool": schema } });

    // Missing "a" and "b", wrong type for "c", extra field "z"
    const result = v.validate({ c: "not-bool", z: 1 }, "srv", "tool");
    expect(result.pass).toBe(false);
    expect(result.ruleIds).toContain("schema.missing-field");
    expect(result.ruleIds).toContain("schema.type-mismatch");
    expect(result.ruleIds).toContain("schema.extra-field");
    expect(result.violations.length).toBeGreaterThanOrEqual(4); // 2 missing + 1 type + 1 extra
  });
});
