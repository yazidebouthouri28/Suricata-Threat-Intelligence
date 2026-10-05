export interface ThreatIntelEntry {
  indicator: string;
  type: 'ip' | 'domain';
  malicious: boolean;
  threat_source: string;
  confidence_score: number;
  threat_categories: string[];
  checked_at: string;
}
