import { completeWithLlm, isLlmConfigured } from './llm-client';
import { semanticSearch } from '../rag/knowledge-base';
import {
  AgentAnalyzeRequest,
  AgentAnalyzeResponse,
  AgentIoc,
  IndicatorType,
} from './types';

function buildSearchQuery(request: AgentAnalyzeRequest): string {
  const parts = [
    request.indicator,
    request.type,
    ...(request.categories ?? []),
    ...(request.signatures ?? []),
    ...(request.threatIntel?.threatCategories ?? []),
  ];
  return parts.filter(Boolean).join(' ');
}

function detectIndicatorType(value: string): IndicatorType {
  if (/^[a-f0-9]{32}$/i.test(value) || /^[a-f0-9]{64}$/i.test(value)) {
    return 'hash';
  }
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value) || value.includes(':')) {
    return 'ip';
  }
  return 'domain';
}

function buildIocs(request: AgentAnalyzeRequest): AgentIoc[] {
  const iocs: AgentIoc[] = [
    {
      type: request.type.toUpperCase(),
      value: request.indicator,
      description: 'Indicator submitted for analysis',
    },
  ];

  const relatedAlerts = request.relatedAlerts ?? [];
  const seen = new Set<string>([request.indicator]);

  for (const alert of relatedAlerts) {
    for (const ip of [alert.srcIp, alert.destIp]) {
      if (ip && ip !== '-' && !seen.has(ip)) {
        seen.add(ip);
        iocs.push({
          type: 'IP',
          value: ip,
          description: `Observed in alert: ${alert.signature}`,
        });
      }
    }
  }

  for (const signature of request.signatures ?? []) {
    iocs.push({
      type: 'Signature',
      value: signature,
      description: 'Suricata rule triggered for this asset',
    });
  }

  return iocs.slice(0, 12);
}

function buildRemediation(
  request: AgentAnalyzeRequest,
  mitreTechniques: string[],
): string[] {
  const steps = new Set<string>();
  const categories = (request.categories ?? []).map((c) => c.toLowerCase());
  const malicious = request.threatIntel?.malicious ?? false;

  if (malicious || (request.alertCount ?? 0) > 0) {
    steps.add(`Block or isolate traffic involving ${request.indicator} at the firewall while investigation continues.`);
  }

  if (categories.some((c) => c.includes('reconnaissance') || c.includes('scan'))) {
    steps.add('Restrict exposure of management interfaces and enable alerting on scanner user-agents.');
  }

  if (categories.some((c) => c.includes('brute force'))) {
    steps.add('Enforce MFA, rotate credentials, and disable default accounts on affected services.');
  }

  if (categories.some((c) => c.includes('privilege') || c.includes('sql injection'))) {
    steps.add('Patch vulnerable applications immediately and deploy WAF/virtual patching for known CVEs.');
  }

  if (categories.some((c) => c.includes('dos') || c.includes('ddos') || c.includes('udp flood'))) {
    steps.add('Enable rate limiting and upstream DDoS protection; close unnecessary UDP services.');
  }

  if (categories.some((c) => c.includes('man in the middle'))) {
    steps.add('Inspect TCP/session anomalies and verify TLS certificate pinning on critical services.');
  }

  if (mitreTechniques.includes('T1071')) {
    steps.add('Review outbound DNS/HTTP connections and block known C2 domains from threat feeds.');
  }

  steps.add('Enrich the indicator in VirusTotal/URLhaus and add confirmed IoCs to blocklists.');
  steps.add('Document findings and open an incident ticket if impact is confirmed.');

  return [...steps];
}

function buildRuleBasedSummary(request: AgentAnalyzeRequest, mitreTechniques: string[]): string {
  const alertCount = request.alertCount ?? 0;
  const ti = request.threatIntel;
  const typeLabel = request.type.toUpperCase();
  const lines: string[] = [];

  lines.push(
    `${typeLabel} ${request.indicator} appears ${alertCount} time(s) in Suricata alerts within the loaded capture window.`,
  );

  if (ti) {
    lines.push(
      `Threat intelligence marks this indicator as ${ti.malicious ? 'malicious' : 'benign'} (confidence ${ti.confidenceScore}%, source: ${ti.threatSource}).`,
    );
    if (ti.threatCategories.length) {
      lines.push(`Associated threat categories: ${ti.threatCategories.join(', ')}.`);
    }
  }

  if (request.categories?.length) {
    lines.push(`Detected attack patterns: ${request.categories.join(', ')}.`);
  }

  if (mitreTechniques.length) {
    lines.push(`Mapped MITRE ATT&CK techniques: ${mitreTechniques.join(', ')}.`);
  }

  return lines.join(' ');
}

function parseLlmSections(content: string): {
  summary: string;
  remediation: string[];
} | null {
  try {
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return null;
    }
    const parsed = JSON.parse(jsonMatch[0]) as {
      summary?: string;
      remediation?: string[];
    };
    if (!parsed.summary) {
      return null;
    }
    return {
      summary: parsed.summary,
      remediation: Array.isArray(parsed.remediation) ? parsed.remediation : [],
    };
  } catch {
    return null;
  }
}

export async function analyzeIndicator(
  request: AgentAnalyzeRequest,
): Promise<AgentAnalyzeResponse> {
  const indicator = request.indicator.trim();
  const type = request.type || detectIndicatorType(indicator);
  const normalizedRequest = { ...request, indicator, type };

  const ragResults = semanticSearch(buildSearchQuery(normalizedRequest), 5);
  const mitreTechniques = ragResults
    .filter((result) => result.document.kind === 'mitre')
    .map((result) => result.document.id);

  const ragSources = ragResults.map((result) => ({
    id: result.document.id,
    title: result.document.title,
    source: result.document.source,
    excerpt: result.document.content.slice(0, 220) + (result.document.content.length > 220 ? '…' : ''),
    score: Math.round(result.score * 100) / 100,
  }));

  const iocs = buildIocs(normalizedRequest);
  let summary = buildRuleBasedSummary(normalizedRequest, mitreTechniques);
  let remediation = buildRemediation(normalizedRequest, mitreTechniques);
  let mode: 'llm' | 'rules' = 'rules';

  if (isLlmConfigured()) {
    const contextBlock = [
      `Indicator: ${indicator} (${type})`,
      `Alert count: ${normalizedRequest.alertCount ?? 0}`,
      `Categories: ${(normalizedRequest.categories ?? []).join(', ') || 'none'}`,
      `Signatures: ${(normalizedRequest.signatures ?? []).join(' | ') || 'none'}`,
      `Threat intel: ${JSON.stringify(normalizedRequest.threatIntel ?? null)}`,
      `RAG documents:\n${ragResults
        .map((r) => `- [${r.document.id}] ${r.document.title}: ${r.document.content}`)
        .join('\n')}`,
    ].join('\n');

    const llmContent = await completeWithLlm({
      messages: [
        {
          role: 'system',
          content:
            'You are a SOC analyst assistant. Respond ONLY with valid JSON: {"summary":"...","remediation":["..."]}. Summary covers asset context, risk, and IoCs. Remediation lists actionable steps.',
        },
        {
          role: 'user',
          content: contextBlock,
        },
      ],
    });

    if (llmContent) {
      const parsed = parseLlmSections(llmContent);
      if (parsed) {
        summary = parsed.summary;
        if (parsed.remediation.length) {
          remediation = parsed.remediation;
        }
        mode = 'llm';
      }
    }
  }

  return {
    indicator,
    type,
    summary,
    iocs,
    remediation,
    ragSources,
    mitreTechniques,
    mode,
    generatedAt: new Date().toISOString(),
  };
}
