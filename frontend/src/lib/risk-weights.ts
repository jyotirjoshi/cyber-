import type { RiskWeights } from "./types";

export const RISK_WEIGHT_KEYS: readonly (keyof RiskWeights)[] = [
  "severity", "exploitation", "exploit_probability", "exposure",
  "asset_criticality", "ransomware",
];

export function totalRiskWeights(weights: RiskWeights): number {
  return RISK_WEIGHT_KEYS.reduce((total, key) => total + weights[key], 0);
}
