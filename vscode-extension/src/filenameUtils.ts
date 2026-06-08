export function extractSuggestedFilename(text: string): string | undefined {
  const patterns = [
    /(?:^|\n)\s*(?:Suggested filename|Filename):\s*[`"']?([a-zA-Z0-9_./-]+\.py)[`"']?\s*(?:\n|$)/im,
    /(?:^|\n)\s*#\s*vibecodeguide-filename:\s*([a-zA-Z0-9_./-]+\.py)\s*(?:\n|$)/im,
  ];
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match?.[1]) {
      return sanitizeFilename(match[1]);
    }
  }
  return undefined;
}

export function deriveFilenameFromPrompt(prompt: string): string {
  const words = prompt
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, " ")
    .split(/\s+/)
    .filter((word) => word.length > 2 && !STOP_WORDS.has(word))
    .slice(0, 4);
  const base = words.length > 0 ? words.join("_") : "generated_module";
  return sanitizeFilename(`${base}.py`);
}

export function sanitizeFilename(name: string): string {
  const basename = name.split(/[/\\]/).pop() ?? name;
  const stem = basename.replace(/\.py$/i, "");
  const safe = stem
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 64);
  return `${safe || "generated_module"}.py`;
}

const STOP_WORDS = new Set([
  "the",
  "and",
  "for",
  "that",
  "with",
  "this",
  "from",
  "create",
  "write",
  "make",
  "build",
  "function",
  "python",
  "code",
  "using",
  "please",
  "need",
  "want",
  "help",
  "secure",
  "safely",
]);
