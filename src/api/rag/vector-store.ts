export interface KnowledgeDocument {
  id: string;
  title: string;
  source: string;
  content: string;
  keywords: string[];
  kind: 'mitre' | 'report';
}

export interface SearchResult {
  document: KnowledgeDocument;
  score: number;
}

const STOP_WORDS = new Set([
  'a', 'an', 'the', 'and', 'or', 'of', 'to', 'in', 'on', 'for', 'with', 'is', 'are',
  'was', 'were', 'be', 'by', 'at', 'from', 'as', 'that', 'this', 'it', 'may',
]);

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s.-]/g, ' ')
    .split(/\s+/)
    .filter((token) => token.length > 2 && !STOP_WORDS.has(token));
}

function termFrequency(tokens: string[]): Map<string, number> {
  const tf = new Map<string, number>();
  for (const token of tokens) {
    tf.set(token, (tf.get(token) ?? 0) + 1);
  }
  return tf;
}

function vectorFromTf(tf: Map<string, number>, idf: Map<string, number>): Map<string, number> {
  const vector = new Map<string, number>();
  for (const [term, count] of tf) {
    vector.set(term, count * (idf.get(term) ?? 0));
  }
  return vector;
}

function magnitude(vector: Map<string, number>): number {
  let sum = 0;
  for (const value of vector.values()) {
    sum += value * value;
  }
  return Math.sqrt(sum);
}

function cosineSimilarity(a: Map<string, number>, b: Map<string, number>): number {
  let dot = 0;
  for (const [term, value] of a) {
    dot += value * (b.get(term) ?? 0);
  }
  const magA = magnitude(a);
  const magB = magnitude(b);
  if (magA === 0 || magB === 0) {
    return 0;
  }
  return dot / (magA * magB);
}

export class VectorStore {
  private readonly documents: KnowledgeDocument[] = [];
  private readonly vectors: Map<string, Map<string, number>> = new Map();
  private idf: Map<string, number> = new Map();

  index(documents: KnowledgeDocument[]): void {
    this.documents.length = 0;
    this.documents.push(...documents);
    this.vectors.clear();

    const docTokens = documents.map((doc) =>
      tokenize(`${doc.title} ${doc.content} ${doc.keywords.join(' ')} ${doc.source}`),
    );

    const documentFrequency = new Map<string, number>();
    for (const tokens of docTokens) {
      const unique = new Set(tokens);
      for (const token of unique) {
        documentFrequency.set(token, (documentFrequency.get(token) ?? 0) + 1);
      }
    }

    const totalDocs = documents.length || 1;
    this.idf = new Map(
      [...documentFrequency.entries()].map(([term, df]) => [
        term,
        Math.log((totalDocs + 1) / (df + 1)) + 1,
      ]),
    );

    documents.forEach((doc, index) => {
      const tf = termFrequency(docTokens[index]);
      this.vectors.set(doc.id, vectorFromTf(tf, this.idf));
    });
  }

  search(query: string, limit = 5): SearchResult[] {
    const queryTokens = tokenize(query);
    const queryVector = vectorFromTf(termFrequency(queryTokens), this.idf);

    const results: SearchResult[] = [];
    for (const doc of this.documents) {
      const docVector = this.vectors.get(doc.id);
      if (!docVector) {
        continue;
      }

      let score = cosineSimilarity(queryVector, docVector);

      const queryLower = query.toLowerCase();
      for (const keyword of doc.keywords) {
        if (queryLower.includes(keyword.toLowerCase())) {
          score += 0.15;
        }
      }

      if (score > 0) {
        results.push({ document: doc, score });
      }
    }

    return results.sort((a, b) => b.score - a.score).slice(0, limit);
  }

  listDocuments(): KnowledgeDocument[] {
    return [...this.documents];
  }
}
