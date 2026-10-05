export interface EveEvent {
  timestamp?: string;
  event_type?: string;
  src_ip?: string;
  dest_ip?: string;
  proto?: string;
  alert?: {
    signature?: string;
    category?: string;
    severity?: number;
    action?: string;
  };
}

export interface CountEntry {
  label: string;
  count: number;
}

export interface AlertRow {
  timestamp: string;
  signature: string;
  category: string;
  severity: number;
  srcIp: string;
  destIp: string;
  action: string;
}

export interface DashboardStats {
  totalEvents: number;
  alertCount: number;
  flowCount: number;
  firstTimestamp: string | null;
  lastTimestamp: string | null;
  eventTypes: CountEntry[];
  alertCategories: CountEntry[];
  alertSeverities: CountEntry[];
  protocols: CountEntry[];
  topSignatures: CountEntry[];
  topSourceIps: CountEntry[];
  topDestIps: CountEntry[];
  alertsTimeline: CountEntry[];
  recentAlerts: AlertRow[];
}

export const SEVERITY_LABELS: Record<number, string> = {
  1: 'High',
  2: 'Medium',
  3: 'Low',
};
