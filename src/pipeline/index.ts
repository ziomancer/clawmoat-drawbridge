/**
 * DrawbridgePipeline: full orchestration runner that routes content through
 * validation stages, scanner, frequency tracking, and audit emission.
 *
 * In v0.1, use DrawbridgeScanner directly for ClawMoat-powered scanning.
 * The full pipeline orchestration lands in v0.2.
 *
 * NOT IMPLEMENTED in v0.1. Placeholder for pipeline type stability.
 */

import type { DrawbridgePipelineConfig } from "../types/pipeline.js";
import type { PipelineInput, PipelineResult } from "../types/pipeline.js";

export class DrawbridgePipeline {
  constructor(_config?: DrawbridgePipelineConfig) {
    // Configuration accepted but not acted on in v0.1
  }

  /** @throws {Error} Not implemented in v0.1 */
  async inspect(_input: PipelineInput): Promise<PipelineResult> {
    throw new Error(
      "DrawbridgePipeline.inspect() is not implemented in v0.1. " +
      "Use DrawbridgeScanner directly for ClawMoat-powered scanning. " +
      "See https://github.com/vigilharbor/clawmoat-drawbridge-sanitizer for roadmap.",
    );
  }
}
