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
    name: "해태",
    romanizedName: "Haetae",
    mission: "환경, 신뢰 경계, 엔드포인트와 인증·인가 공격 표면을 모델링합니다.",
    tools: ["workspace_summary", "attack_surface", "call_path"],
  },
  {
    role: "static",
    code: "maenun",
    name: "매눈",
    romanizedName: "Maenun",
    mission: "lite/deep 정적 분석과 source-to-sink 리치어빌리티를 검증합니다.",
    tools: ["finding_context", "call_path", "attack_surface"],
  },
  {
    role: "dynamic",
    code: "salgwaengi",
    name: "살쾡이",
    romanizedName: "Salgwaengi",
    mission: "승인된 owned fixture에서 비파괴 동적 검증과 대조군을 실행합니다.",
    tools: ["finding_context", "call_path", "harness_plan"],
  },
  {
    role: "cve",
    code: "geobukseon",
    name: "거북선",
    romanizedName: "Geobukseon",
    mission: "CVE의 버전 노출, 애플리케이션 리치어빌리티와 실제 적용성을 분리합니다.",
    tools: ["workspace_summary", "call_path", "harness_plan"],
  },
  {
    role: "synthesis",
    code: "jangseung",
    name: "장승",
    romanizedName: "Jangseung",
    mission: "정적·동적 증거를 통합해 위험, 발생 가능성과 코드 수준 대응을 정리합니다.",
    tools: ["finding_context", "call_path", "attack_surface"],
  },
  {
    role: "steward",
    code: "hanul",
    name: "한울",
    romanizedName: "Hanul",
    mission: "품질 지표를 분석하고 자동 적용 없는 평가·승인형 개선안을 제안합니다.",
    tools: ["workspace_summary"],
  },
];
