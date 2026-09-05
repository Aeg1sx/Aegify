export type AgentRole =
  | "surface"
  | "static"
  | "dynamic"
  | "cve"
  | "synthesis"
  | "steward";

export interface AgentIdentity {
  role: AgentRole;
  code: string;
  name: string;
  romanizedName: string;
  mission: string;
  tools: string[];
}

export const SECURITY_AGENTS: AgentIdentity[] = [
  {
    role: "surface",
    code: "haetae",
    name: "Haetae",
    romanizedName: "Haetae",
    mission: "Map services, trust boundaries, endpoints, and authentication and authorization evidence.",
    tools: ["workspace_summary", "attack_surface", "call_path"],
  },
  {
    role: "static",
    code: "maenun",
    name: "Maenun",
    romanizedName: "Maenun",
    mission: "Review static findings in lite or deep mode and trace recorded source-to-sink paths.",
    tools: ["finding_context", "call_path", "attack_surface"],
  },
  {
    role: "dynamic",
    code: "salgwaengi",
    name: "Salgwaengi",
    romanizedName: "Salgwaengi",
    mission: "Coordinate approved, non-destructive fixture validation with negative controls.",
    tools: ["finding_context", "call_path", "harness_plan"],
  },
  {
    role: "cve",
    code: "geobukseon",
    name: "Geobukseon",
    romanizedName: "Geobukseon",
    mission: "Separate affected versions, application reachability, and environment applicability.",
    tools: ["workspace_summary", "call_path", "harness_plan"],
  },
  {
    role: "synthesis",
    code: "jangseung",
    name: "Jangseung",
    romanizedName: "Jangseung",
    mission: "Reconcile static and runtime evidence into risk and code-level remediation guidance.",
    tools: ["finding_context", "call_path", "attack_surface"],
  },
  {
    role: "steward",
    code: "hanul",
    name: "Hanul",
    romanizedName: "Hanul",
    mission: "Review quality metrics and propose evaluation-gated improvements without automatic changes.",
    tools: ["workspace_summary"],
  },
];
