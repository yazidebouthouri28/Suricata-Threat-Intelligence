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
