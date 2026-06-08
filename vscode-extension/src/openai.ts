import { SECURE_CODE_SYSTEM_PROMPT } from "./systemPrompt";

export class OpenAiError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OpenAiError";
  }
}

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface OpenAiOptions {
  apiKey: string;
  baseUrl: string;
  model: string;
  timeoutMs: number;
}

export async function chatCompletion(
  options: OpenAiOptions,
  messages: ChatMessage[],
): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs);

  try {
    const response = await fetch(`${options.baseUrl.replace(/\/$/, "")}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${options.apiKey}`,
      },
      body: JSON.stringify({
        model: options.model,
        messages: [{ role: "system", content: SECURE_CODE_SYSTEM_PROMPT }, ...messages],
        temperature: 0.2,
      }),
      signal: controller.signal,
    });

    const text = await response.text();
    let payload: unknown;
    try {
      payload = text ? JSON.parse(text) : {};
    } catch {
      throw new OpenAiError(`Invalid JSON from OpenAI: ${text.slice(0, 200)}`);
    }

    if (!response.ok) {
      const detail =
        typeof payload === "object" &&
        payload !== null &&
        "error" in payload &&
        typeof (payload as { error: unknown }).error === "object" &&
        (payload as { error: { message?: string } }).error !== null
          ? (payload as { error: { message?: string } }).error.message
          : `OpenAI request failed (${response.status})`;
      throw new OpenAiError(detail ?? `OpenAI request failed (${response.status})`);
    }

    const content =
      typeof payload === "object" &&
      payload !== null &&
      "choices" in payload &&
      Array.isArray((payload as { choices: unknown[] }).choices) &&
      (payload as { choices: Array<{ message?: { content?: string } }> }).choices[0]?.message?.content;

    if (!content) {
      throw new OpenAiError("OpenAI returned an empty response.");
    }

    return content;
  } catch (err) {
    if (err instanceof OpenAiError) {
      throw err;
    }
    if (err instanceof Error && err.name === "AbortError") {
      throw new OpenAiError(`OpenAI request timed out after ${options.timeoutMs}ms`);
    }
    throw new OpenAiError(err instanceof Error ? err.message : String(err));
  } finally {
    clearTimeout(timer);
  }
}
