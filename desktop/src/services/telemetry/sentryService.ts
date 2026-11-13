import type * as SentryType from "@sentry/react";
import packageInfo from "../../../package.json";
import { telemetryPreference, setDiagnosticReceiver, configureTelemetryDefaults } from "./telemetryStore";
import { sanitizeDiagnosticEvent } from "./sanitize";
import diagnosticsConfig from "../../../diagnostics.config.json";

configureTelemetryDefaults(diagnosticsConfig.remote);

const dsn = String(import.meta.env.VITE_SENTRY_DSN || "").trim();
export const remoteDiagnosticsConfigured = (() => { try { const url = new URL(dsn); return url.protocol === "https:" && !!url.username && !url.password && /^\/\d+$/.test(url.pathname); } catch { return false; } })();
const release = `${packageInfo.name}@${packageInfo.version}`;
let sdk: typeof SentryType | undefined;
let generation = 0;
let stop = () => {};

export function captureUiError(error: unknown) {
  if (telemetryPreference.getSnapshot().enabled) sdk?.captureException(error, { tags: { layer: "ui", code: "UI_UNHANDLED" } });
}

export function startRemoteDiagnostics() {
  const configure = async () => {
    const current = ++generation;
    stop(); stop = () => {}; sdk = undefined; setDiagnosticReceiver();
    const preference = telemetryPreference.getSnapshot();
    if (!preference.enabled || !remoteDiagnosticsConfigured) return;
    const sentry = await import("@sentry/react");
    if (generation !== current || !telemetryPreference.getSnapshot().enabled) return;
    const controller = new AbortController();
    const active = () => current === generation && telemetryPreference.getSnapshot().enabled;
    const environment = import.meta.env.MODE;
    const filter = (event: unknown) => active() ? sanitizeDiagnosticEvent(event, release, environment) : null;
    const client = sentry.init({
      dsn, release, environment, defaultIntegrations: false, sendClientReports: false,
      dataCollection: { userInfo: false, cookies: false, httpHeaders: false, httpBodies: [], urlQueryParams: false, graphQL: { document: false, variables: false }, genAI: { inputs: false, outputs: false }, mcp: { inputs: false, outputs: false }, databaseQueryData: false, queues: false, stackFrameVariables: false, frameContextLines: 0 },
      // Keep operation timings on the transaction path covered by our sanitizer.
      // Streaming spans use a separate SDK pipeline and bypass beforeSendTransaction.
      traceLifecycle: "static", maxBreadcrumbs: 0, tracePropagationTargets: [],
      ...(preference.traceSampleRate > 0 ? { tracesSampleRate: preference.traceSampleRate } : {}),
      beforeSend: event => filter(event) as typeof event | null,
      beforeSendTransaction: event => filter(event) as typeof event | null,
      transport(options) {
        const transport = sentry.makeFetchTransport({ ...options, fetchOptions: { signal: controller.signal } });
        return { send: envelope => active() ? transport.send(envelope) : Promise.resolve({}), flush: timeout => transport.flush(timeout) };
      },
    });
    sdk = sentry;
    const onError = (event: ErrorEvent) => captureUiError(event.error ?? new Error("UI_UNHANDLED"));
    const onRejection = (event: PromiseRejectionEvent) => captureUiError(event.reason);
    window.addEventListener("error", onError);
    window.addEventListener("unhandledrejection", onRejection);
    setDiagnosticReceiver(event => {
      if (!active()) return;
      if (event.status === "failed" && event.code) sentry.captureMessage(event.code, { level: "error", tags: { layer: event.layer, code: event.code } });
      if (event.durationMs !== undefined && preference.traceSampleRate > 0) {
        const end = Date.now() / 1000;
        const span = sentry.startInactiveSpan({ name: `operation.${event.layer}`, op: "operation", parentSpan: null, forceTransaction: true, startTime: end - event.durationMs / 1000 });
        span.setStatus({ code: event.status === "failed" ? 2 : 1 });
        span.end(end);
      }
    });
    stop = () => {
      controller.abort();
      window.removeEventListener("error", onError);
      window.removeEventListener("unhandledrejection", onRejection);
      void client?.close(0);
    };
  };
  const apply = () => { void configure().catch(() => { /* Collection never blocks startup. */ }); };
  apply();
  const unsubscribe = telemetryPreference.subscribe(apply);
  return () => { ++generation; unsubscribe(); stop(); sdk = undefined; setDiagnosticReceiver(); };
}
