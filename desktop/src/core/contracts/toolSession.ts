/** Identifiers used only to collect related observations on the canvas. */
export interface ToolSession {
  connectionId: string;
  target: string;
  subject?: string;
  sessionId?: string;
}

function readId(source: unknown, keys: string[]) {
  if (!source || typeof source !== "object") return;
  for (const key of keys) {
    const value = (source as Record<string, unknown>)[key];
    if (typeof value === "string" && value.length) return value;
    if (typeof value === "number" && Number.isFinite(value)) return String(value);
  }
}

export function readToolSession(mcp: unknown): ToolSession | undefined {
  if (!mcp || typeof mcp !== "object") return;
  const { connectionId, target, arguments: args, result } = mcp as Record<string, unknown>;
  if (typeof connectionId !== "string" || !connectionId || typeof target !== "string" || !target) return;
  const content = result && typeof result === "object" && "structuredContent" in result ? result.structuredContent : undefined;
  const sessionKeys = ["session_id", "sessionId", "session"];
  const subject = readId(args, ["sample_id", "sampleId", "sample_path", "binary_path", "program_path", "program_name", "program", "target"]);
  return {
    connectionId, target, subject: subject === target ? undefined : subject,
    sessionId: readId(args, sessionKeys) ?? readId(content, sessionKeys),
  };
}
