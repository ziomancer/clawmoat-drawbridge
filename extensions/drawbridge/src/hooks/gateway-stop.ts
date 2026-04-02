/**
 * gateway:stop hook — teardown plugin state.
 * Clears the cache sweep interval to prevent leaks on gateway reload.
 */

import type { PluginState } from "../pipeline-factory.js";

export function handleGatewayStop(state: PluginState): void {
  try {
    state.teardown();
  } catch (err) {
    console.warn("[drawbridge:gateway_stop] Teardown error:", (err as Error).message ?? err);
  }
}
