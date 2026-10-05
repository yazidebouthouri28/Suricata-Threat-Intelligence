import { completeWithLlm, isLlmConfigured } from './llm-client';
import { ExplainKind, ExplainRequest, ExplainResponse, ExplainSource } from './explain-types';
import { semanticSearch } from '../rag/knowledge-base';

const KIND_LABELS: Record<ExplainKind, string> = {
  signature: 'Suricata signature',
  category: 'Attack category',
  severity: 'Alert severity',
  event_type: 'EVE event type',
  protocol: 'Network protocol',
  metric: 'Dashboard metric',
  threat_intel: 'Threat intelligence',
  action: 'Suricata action',
  general: 'Security concept',
};

function buildSearchQuery(request: ExplainRequest): string {
  const contextParts = Object.entries(request.context ?? {})
    .filter(([, value]) => value !== null && value !== undefined)
    .map(([key, value]) => `${key}: ${String(value)}`);

  return [request.term, request.kind, ...contextParts].join(' ');
}

function buildTitle(kind: ExplainKind, term: string): string {
  return `${KIND_LABELS[kind]}: ${term}`;
}

function buildRagExplanation(
  request: ExplainRequest,
  sources: ExplainSource[],
): string {
  const context = request.context ?? {};
  const paragraphs: string[] = [];

  paragraphs.push(
    `Here is a contextual explanation of "${request.term}" (${KIND_LABELS[request.kind].toLowerCase()}) based on your Suricata dashboard data and indexed threat knowledge.`,
  );

  if (context['count'] !== undefined) {
    paragraphs.push(
      `In the current capture, this item appears ${context['count']} time(s), which helps prioritize whether it is background noise or an active pattern worth investigating.`,
    );
  }

  if (context['relatedAlerts']) {
    paragraphs.push(
      `Related alert context from your logs: ${String(context['relatedAlerts'])}.`,
    );
  }

  if (sources.length) {
    const insights = sources
      .slice(0, 3)
      .map((source) => `${source.title} (${source.source}): ${source.excerpt}`)
      .join('\n\n');
    paragraphs.push(
      `Relevant knowledge retrieved via semantic search:\n\n${insights}`,
    );
  } else {
    paragraphs.push(
      'No close match was found in the MITRE ATT&CK / threat-report index, so focus on the raw Suricata field and surrounding alerts to validate impact.',
    );
  }

  paragraphs.push(
    'Practical takeaway: treat this as a lead, correlate with source/destination IPs, then confirm whether the behavior is expected for your environment before blocking or escalating.',
  );

  return paragraphs.join('\n\n');
}

function parseLlmExplanation(content: string): string | null {
  try {
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]) as { explanation?: string };
      if (parsed.explanation?.trim()) {
        return parsed.explanation.trim();
      }
    }
  } catch {
    // fall through to raw text
  }

  const trimmed = content.trim();
  return trimmed || null;
}

export async function explainTerm(request: ExplainRequest): Promise<ExplainResponse> {
  const term = request.term.trim();
  const kind = request.kind ?? 'general';
  const ragResults = semanticSearch(buildSearchQuery({ ...request, term, kind }), 4);

  const ragSources: ExplainSource[] = ragResults.map((result) => ({
    id: result.document.id,
    title: result.document.title,
    source: result.document.source,
    excerpt: result.document.content.slice(0, 240) + (result.document.content.length > 240 ? '…' : ''),
    score: Math.round(result.score * 100) / 100,
  }));

  let explanation = buildRagExplanation({ ...request, term, kind }, ragSources);
  let mode: 'llm' | 'rag' = 'rag';

  if (isLlmConfigured()) {
    const contextJson = JSON.stringify(request.context ?? {}, null, 2);
    const ragBlock = ragResults
      .map((r) => `[${r.document.id}] ${r.document.title}: ${r.document.content}`)
      .join('\n');

    const llmContent = await completeWithLlm({
      messages: [
        {
          role: 'system',
          content:
            'You explain cybersecurity dashboard items to non-experts. Respond ONLY with JSON: {"explanation":"..."}. Use 2-4 short paragraphs in plain language. Mention what it means, why it matters in SOC work, and one practical next step. Use the provided dashboard context and RAG excerpts.',
        },
        {
          role: 'user',
          content: [
            `Explain this dashboard item.`,
            `Term: ${term}`,
            `Type: ${KIND_LABELS[kind]}`,
            `Dashboard context:\n${contextJson}`,
            `RAG knowledge:\n${ragBlock || 'none'}`,
          ].join('\n\n'),
        },
      ],
      temperature: 0.35,
    });

    const parsed = llmContent ? parseLlmExplanation(llmContent) : null;
    if (parsed) {
      explanation = parsed;
      mode = 'llm';
    }
  }

  return {
    term,
    kind,
    title: buildTitle(kind, term),
    explanation,
    ragSources,
    mode,
    generatedAt: new Date().toISOString(),
  };
}
