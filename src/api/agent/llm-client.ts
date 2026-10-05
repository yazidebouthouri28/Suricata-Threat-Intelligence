export interface LlmMessage {
  role: 'system' | 'user' | 'assistant';
  content: string;
}

export interface LlmCompletionOptions {
  messages: LlmMessage[];
  temperature?: number;
}

export async function completeWithLlm(options: LlmCompletionOptions): Promise<string | null> {
  const apiKey = process.env['OPENAI_API_KEY'] ?? process.env['LLM_API_KEY'];
  if (!apiKey) {
    return null;
  }

  const baseUrl = (process.env['OPENAI_BASE_URL'] ?? 'https://api.openai.com/v1').replace(/\/$/, '');
  const model = process.env['LLM_MODEL'] ?? 'gpt-4o-mini';

  const response = await fetch(`${baseUrl}/chat/completions`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model,
      temperature: options.temperature ?? 0.2,
      messages: options.messages,
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`LLM request failed (${response.status}): ${errorText}`);
  }

  const payload = (await response.json()) as {
    choices?: Array<{ message?: { content?: string } }>;
  };

  return payload.choices?.[0]?.message?.content?.trim() ?? null;
}

export function isLlmConfigured(): boolean {
  return Boolean(process.env['OPENAI_API_KEY'] ?? process.env['LLM_API_KEY']);
}
