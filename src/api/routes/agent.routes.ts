import { Router } from 'express';

import { analyzeIndicator } from '../agent/analyzer';
import { explainTerm } from '../agent/explainer';
import { ExplainRequest } from '../agent/explain-types';
import { isLlmConfigured } from '../agent/llm-client';
import { AgentAnalyzeRequest } from '../agent/types';
import { listKnowledgeDocuments, semanticSearch } from '../rag/knowledge-base';

export function createAgentRouter(): Router {
  const router = Router();

  router.get('/health', (_req, res) => {
    res.json({
      status: 'ok',
      llmConfigured: isLlmConfigured(),
      knowledgeDocuments: listKnowledgeDocuments().length,
    });
  });

  router.get('/knowledge', (_req, res) => {
    res.json(listKnowledgeDocuments());
  });

  router.post('/agent/analyze', async (req, res) => {
    try {
      const body = req.body as AgentAnalyzeRequest;
      if (!body?.indicator?.trim()) {
        res.status(400).json({ error: 'indicator is required' });
        return;
      }

      const result = await analyzeIndicator(body);
      res.json(result);
    } catch (error) {
      console.error('Agent analysis failed', error);
      res.status(500).json({ error: 'Agent analysis failed' });
    }
  });

  router.post('/agent/explain', async (req, res) => {
    try {
      const body = req.body as ExplainRequest;
      if (!body?.term?.trim()) {
        res.status(400).json({ error: 'term is required' });
        return;
      }

      const result = await explainTerm(body);
      res.json(result);
    } catch (error) {
      console.error('Explain request failed', error);
      res.status(500).json({ error: 'Explain request failed' });
    }
  });

  router.post('/rag/search', (req, res) => {
    const query = String(req.body?.query ?? '').trim();
    const limit = Number(req.body?.limit ?? 5);
    if (!query) {
      res.status(400).json({ error: 'query is required' });
      return;
    }

    const results = semanticSearch(query, limit).map((result) => ({
      id: result.document.id,
      title: result.document.title,
      source: result.document.source,
      excerpt: result.document.content.slice(0, 280),
      score: result.score,
    }));
    res.json({ query, results });
  });

  return router;
}
