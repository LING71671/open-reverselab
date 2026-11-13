import { HEALTH_CODES, HEALTH_LAYERS } from "../../core/contracts/health.ts";

const object = (v: unknown): Record<string, any> => v && typeof v === "object" ? v as Record<string, any> : {};
const id = (v: unknown, length: number) => typeof v === "string" && new RegExp(`^[a-f0-9]{${length}}$`).test(v) ? v : undefined;
const finite = (v: unknown) => typeof v === "number" && Number.isFinite(v) ? v : undefined;
const errorTypes = new Set(["Error", "TypeError", "RangeError", "ReferenceError", "SyntaxError", "URIError", "EvalError", "AggregateError"]);
export function sanitizeDiagnosticEvent(input: unknown, release: string, environment: string): Record<string, any> | null {
  const event = object(input);
  const layer = HEALTH_LAYERS.includes(event.tags?.layer) ? event.tags.layer : "ui";
  const code = HEALTH_CODES.includes(event.tags?.code) ? event.tags.code : "UI_UNHANDLED";
  const clean: Record<string, any> = {
    event_id: id(event.event_id, 32), timestamp: finite(event.timestamp), platform: "javascript", release, environment,
    sdk: { settings: { infer_ip: "never" } },
    // Relay infers location from the connection even when IP storage is disabled.
    // An explicit empty geo object prevents that server-side enrichment.
    user: { geo: {} },
  };
  if (event.type === "transaction") {
    if (!HEALTH_LAYERS.some(l => event.transaction === `operation.${l}`)) return null;
    const trace = object(event.contexts?.trace);
    return { ...clean, type: "transaction", transaction: event.transaction, start_timestamp: finite(event.start_timestamp), spans: [], contexts: { trace: { trace_id: id(trace.trace_id, 32), span_id: id(trace.span_id, 16), op: "operation", status: ["ok", "internal_error"].includes(trace.status) ? trace.status : undefined } } };
  }
  clean.level = event.level === "warning" ? "warning" : "error";
  clean.tags = { layer, code };
  clean.fingerprint = [layer, code];
  const values = Array.isArray(event.exception?.values) ? event.exception.values : [];
  clean.exception = { values: values.slice(0, 1).map((value: any) => ({
    type: errorTypes.has(value.type) ? value.type : "Error",
    value: code,
    // Only application build assets are useful here; never retain filesystem or target URLs.
    stacktrace: { frames: (Array.isArray(value.stacktrace?.frames) ? value.stacktrace.frames : []).flatMap((frame: any) => {
      const file = typeof frame.filename === "string" ? frame.filename.match(/(?:^|\/)assets\/([A-Za-z0-9_-]+\.js)$/)?.[1] : undefined;
      return file ? [{ filename: `app:///assets/${file}`, lineno: finite(frame.lineno), colno: finite(frame.colno), in_app: true }] : [];
    }).slice(-40) },
  })) };
  if (!clean.exception.values.length) { delete clean.exception; clean.message = code; }
  return clean;
}
