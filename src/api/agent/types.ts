export type IndicatorType = 'ip' | 'domain' | 'hash';

export interface AgentAlertContext {
  timestamp: string;
  signature: string;
  category: string;
  severity: number;
  srcIp: string;
  destIp: string;
}

export interface AgentThreatIntelContext {
  malicious: boolean;
  confidenceScore: number;
  threatCategories: string[];
  threatSource: string;
}

export interface AgentAnalyzeRequest {
  indicator: string;
  type: IndicatorType;
  relatedAlerts?: AgentAlertContext[];
  alertCount?: number;
  categories?: string[];
  signatures?: string[];
  threatIntel?: AgentThreatIntelContext | null;
}

export interface AgentIoc {
  type: string;
  value: string;
  description: string;
}

export interface AgentSource {
  id: string;
  title: string;
  source: string;
  excerpt: string;
  score: number;
}

export interface AgentAnalyzeResponse {
  indicator: string;
  type: IndicatorType;
  summary: string;
  iocs: AgentIoc[];
  remediation: string[];
  ragSources: AgentSource[];
  mitreTechniques: string[];
  mode: 'llm' | 'rules';
  generatedAt: string;
}
