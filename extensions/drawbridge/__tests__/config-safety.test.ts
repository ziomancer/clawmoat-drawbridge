import { describe, it, expect } from "vitest";
import { resolveConfig } from "../src/config.js";

describe("Config safety", () => {
  it("exemptChannels is frozen after resolution", () => {
    const config = resolveConfig({ exemptChannels: ["chan-1"] });
    expect(Object.isFrozen(config.exemptChannels)).toBe(true);
    expect(() => {
      (config.exemptChannels as string[]).push("chan-2");
    }).toThrow();
  });

  it("exemptSenders is frozen after resolution", () => {
    const config = resolveConfig({ exemptSenders: ["user-1"] });
    expect(Object.isFrozen(config.exemptSenders)).toBe(true);
    expect(() => {
      (config.exemptSenders as string[]).push("user-2");
    }).toThrow();
  });

  it("mutating input arrays after resolve has no effect", () => {
    const channels = ["chan-1"];
    const senders = ["user-1"];
    const config = resolveConfig({ exemptChannels: channels, exemptSenders: senders });

    channels.push("chan-2");
    senders.push("user-2");

    expect(config.exemptChannels).toEqual(["chan-1"]);
    expect(config.exemptSenders).toEqual(["user-1"]);
  });

  it("defaults are applied correctly", () => {
    const config = resolveConfig();
    expect(config.inboundProfile).toBe("general");
    expect(config.outboundProfile).toBe("customer-service");
    expect(config.blockThreshold).toBe("medium");
    expect(config.direction).toBe("both");
    expect(config.tier2Action).toBe("warn");
    expect(config.blockMessage).toBe("Message blocked by content filter.");
    expect(config.terminateMessage).toBe("Session terminated due to repeated violations.");
    expect(config.redactOutbound).toBe(true);
    expect(config.hashRedactions).toBe(true);
    expect(config.auditSink).toBe("log");
    expect(config.auditVerbosity).toBe("standard");
    expect(config.exemptChannels).toEqual([]);
    expect(config.exemptSenders).toEqual([]);
  });

  it("overrides are applied", () => {
    const config = resolveConfig({
      inboundProfile: "admin",
      tier2Action: "block",
      blockMessage: "Nope.",
    });
    expect(config.inboundProfile).toBe("admin");
    expect(config.tier2Action).toBe("block");
    expect(config.blockMessage).toBe("Nope.");
  });
});
