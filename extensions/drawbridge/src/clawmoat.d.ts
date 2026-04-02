declare module "clawmoat" {
  export class ClawMoat {
    scan(text: string): {
      safe: boolean;
      findings: Array<{ type: string; subtype: string; severity: string; matched: string; position: number }>;
      inbound: { findings: Array<{ type: string; subtype: string; severity: string; matched: string; position: number }>; safe: boolean; severity: string; action: string };
      outbound: { findings: Array<{ type: string; subtype: string; severity: string; matched: string; position: number }>; safe: boolean; severity: string; action: string };
    };
  }
}
