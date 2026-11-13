import type { AgentMessage } from "../runtime/agentMessages";
import type { PythonExecResult } from "../../services/native/nativeBridge";

/** Sort object keys, but preserve arrays and every value in the observed data. */
export function stableJson(value: unknown): string {
  return JSON.stringify(value, (_key, item) => item && typeof item === "object" && !Array.isArray(item)
    ? Object.fromEntries(Object.keys(item).sort().map(key => [key, item[key]])) : item);
}

function observedText(text: string): string {
  try { return stableJson(JSON.parse(text)); } catch { return text.trim(); }
}

export function observationIdentity(output: Pick<PythonExecResult, "success" | "stdout" | "stderr">) {
  return { success: output.success, stdout: observedText(output.stdout), stderr: output.stderr.trim() };
}

/** Receipt IDs, graph node IDs and runner timings are provenance, not new observations. */
export function peerObservationIdentity(messages: AgentMessage[]) {
  const observations = messages.map(message => {
    let content: unknown = message.payload.content;
    try {
      const value = JSON.parse(message.payload.content);
      const output = value.output || value.execution;
      if (output && typeof output.success === "boolean" && typeof output.stdout === "string" && typeof output.stderr === "string") content = observationIdentity(output);
    } catch { /* Document references and prose remain literal. */ }
    return stableJson({ from: message.from, type: message.type, content, paths: message.payload.evidenceRefs?.flatMap(ref => ref.path ? [ref.path] : []).sort() || [] });
  });
  return [...new Set(observations)].sort();
}

export async function fingerprint(value: unknown): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(stableJson(value)));
  return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, "0")).join("");
}
