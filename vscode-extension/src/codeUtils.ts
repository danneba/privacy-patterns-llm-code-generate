const PYTHON_FENCE = /```(?:python|py)?\s*\n([\s\S]*?)```/gi;

export function extractPythonCode(text: string): string | undefined {
  const blocks: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = PYTHON_FENCE.exec(text)) !== null) {
    const block = match[1].trim();
    if (block) {
      blocks.push(block);
    }
  }
  if (blocks.length === 0) {
    return undefined;
  }
  return blocks.join("\n\n");
}

export function stripCodeFences(text: string): string {
  return text.replace(/```(?:python|py)?\s*\n([\s\S]*?)```/gi, (_, code: string) => code.trim()).trim();
}
