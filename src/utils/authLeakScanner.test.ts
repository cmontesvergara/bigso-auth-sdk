import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { findAuthLeaks } from "../../scripts/scan-auth-artifacts.mjs";

describe("authentication artifact scanner", () => {
  it("accepts sanitized authentication logs", async () => {
    const log = await readFile("test-fixtures/auth-logs/safe.log", "utf8");
    expect(findAuthLeaks(log)).toEqual([]);
  });

  it("detects credentials in an unsafe fixture", async () => {
    const log = await readFile("test-fixtures/auth-logs/unsafe.log", "utf8");
    expect(findAuthLeaks(log).map(({ name }) => name)).toEqual(expect.arrayContaining([
      "JWT",
      "Authorization bearer",
      "refresh token field",
      "token hash field",
    ]));
  });
});
