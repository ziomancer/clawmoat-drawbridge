import { createHash } from "node:crypto";

/** Compute SHA-256 hex digest of a UTF-8 string. */
export function sha256(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}
