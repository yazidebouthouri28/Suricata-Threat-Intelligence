export type IndicatorType = 'ip' | 'domain' | 'hash';

export interface AgentAnalyzeRequest {
  indicator: string;
  type: IndicatorType;
  relatedAlerts?: Array<{
    timestamp: string;
    signature: string;
    category: string;
    severity: number;
    srcIp: string;
    destIp: string;
  }>;
  alertCount?: number;
  categories?: string[];
  signatures?: string[];
  threatIntel?: {
    malicious: boolean;
    confidenceScore: number;
    threatCategories: string[];
    threatSource: string;
  } | null;
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

export interface AgentHealthResponse {
  status: string;
  llmConfigured: boolean;
  knowledgeDocuments: number;
}

export type ExplainKind =
  | 'signature'
  | 'category'
  | 'severity'
  | 'event_type'
  | 'protocol'
  | 'metric'
  | 'threat_intel'
  | 'action'
  | 'general';

export interface ExplainRequest {
  term: string;
  kind: ExplainKind;
  context?: Record<string, unknown>;
}

export interface ExplainSource {
  id: string;
  title: string;
  source: string;
  excerpt: string;
  score: number;
}

export interface ExplainResponse {
  term: string;
  kind: ExplainKind;
  title: string;
  explanation: string;
  ragSources: ExplainSource[];
  mode: 'llm' | 'rag';
  generatedAt: string;
}
