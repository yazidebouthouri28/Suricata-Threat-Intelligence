import express from 'express';

import { createAgentRouter } from './routes/agent.routes';

const app = express();
const port = Number(process.env['AGENT_API_PORT'] ?? 3001);

app.use(express.json({ limit: '1mb' }));
app.use('/api', createAgentRouter());

app.listen(port, () => {
  console.log(`Agent API listening on http://localhost:${port}/api`);
});
