import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { KnowledgeDocument, VectorStore } from './vector-store';

interface RawMitreDoc {
  id: string;
  title: string;
  tactic: string;
  content: string;
  keywords: string[];
}

interface RawReportDoc {
  id: string;
  title: string;
  source: string;
  content: string;
  keywords: string[];
}

let store: VectorStore | null = null;

function knowledgeDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), '../knowledge');
}

function loadDocuments(): KnowledgeDocument[] {
  const mitre = JSON.parse(
    readFileSync(join(knowledgeDir(), 'mitre-attack.json'), 'utf-8'),
  ) as RawMitreDoc[];

  const reports = JSON.parse(
    readFileSync(join(knowledgeDir(), 'threat-reports.json'), 'utf-8'),
  ) as RawReportDoc[];

  return [
    ...mitre.map((doc) => ({
      id: doc.id,
      title: doc.title,
      source: `MITRE ATT&CK · ${doc.tactic}`,
      content: doc.content,
      keywords: doc.keywords,
      kind: 'mitre' as const,
    })),
    ...reports.map((doc) => ({
      id: doc.id,
      title: doc.title,
      source: doc.source,
      content: doc.content,
      keywords: doc.keywords,
      kind: 'report' as const,
    })),
  ];
}

export function getVectorStore(): VectorStore {
  if (!store) {
    store = new VectorStore();
    store.index(loadDocuments());
  }
  return store;
}

export function semanticSearch(query: string, limit = 5) {
  return getVectorStore().search(query, limit);
}

export function listKnowledgeDocuments(): KnowledgeDocument[] {
  return getVectorStore().listDocuments();
}
