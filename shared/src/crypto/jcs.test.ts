import { describe, expect, it } from "vitest";
import { canonicalJson } from "./jcs.ts";
import { EncodingError } from "./errors.ts";

describe("RFC 8785 canonical JSON", () => {
  it("sorts object keys by UTF-16 code units, recursively", () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    // uppercase sorts before lowercase in code-unit order
    expect(canonicalJson({ a: 1, B: 2 })).toBe('{"B":2,"a":1}');
    expect(canonicalJson({ z: 1, é: 2 })).toBe('{"z":1,"é":2}');
    expect(canonicalJson({ outer: { b: 1, a: 2 } })).toBe('{"outer":{"a":2,"b":1}}');
  });

  it("serializes numbers per ECMAScript rules", () => {
    expect(canonicalJson(4.5)).toBe("4.5");
    expect(canonicalJson(1e30)).toBe("1e+30");
    expect(canonicalJson(2e-3)).toBe("0.002");
    expect(canonicalJson(-0)).toBe("0");
    expect(canonicalJson(10)).toBe("10");
  });

  it("escapes strings like JSON.stringify", () => {
    expect(canonicalJson("a\nb")).toBe('"a\\nb"');
    expect(canonicalJson("\u000f")).toBe('"\\u000f"');
    expect(canonicalJson('quote"backslash\\')).toBe('"quote\\"backslash\\\\"');
  });

  it("emits no whitespace and preserves array order", () => {
    expect(canonicalJson([3, 1, 2])).toBe("[3,1,2]");
    expect(canonicalJson({ a: [true, false, null] })).toBe('{"a":[true,false,null]}');
  });

  it("is stable: same value, different construction, same bytes", () => {
    const a = JSON.parse('{"x": 1, "y": {"q": [1, 2]}}');
    const b = { y: { q: [1, 2] }, x: 1 };
    expect(canonicalJson(a)).toBe(canonicalJson(b));
  });

  it("rejects non-JSON values loudly", () => {
    expect(() => canonicalJson(NaN)).toThrow(EncodingError);
    expect(() => canonicalJson(Infinity)).toThrow(EncodingError);
    expect(() => canonicalJson({ a: undefined } as never)).toThrow(EncodingError);
    expect(() => canonicalJson((() => 1) as never)).toThrow(EncodingError);
  });
});
