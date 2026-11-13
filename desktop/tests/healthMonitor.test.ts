import assert from "node:assert/strict";
import test from "node:test";
import { HEALTH_CODES, HEALTH_LAYERS, HealthFault } from "../src/core/contracts/health.ts";
import type { HealthEvent } from "../src/core/contracts/health.ts";
import { classifyFailure, HealthMonitor } from "../src/services/health/healthMonitor.ts";

const event = (id: string, extra: Partial<HealthEvent> = {}): HealthEvent => ({
  eventId: id, goalId: "goal-a", layer: "model", status: "running", timestamp: 1, ...extra,
});

test("all stable codes have a typed classification and a separate short reason", () => {
  for (const code of HEALTH_CODES) {
    const failure = classifyFailure(new HealthFault(code, "diagnostic trace"), "agent");
    assert.equal(failure.code, code);
    assert.equal(failure.detail, "diagnostic trace");
    assert.notEqual(failure.reason, failure.detail);
    assert.ok(failure.reason.length < 30);
    assert.ok(Object.isFrozen(failure));
  }
  assert.equal(classifyFailure(new HealthFault("BUDGET_TIME"), "model").layer, "goal");
  assert.equal(classifyFailure(new Error("timeout"), "tool", { code: "USER_CANCELLED" }).code, "USER_CANCELLED");
});

test("quota 429 errors are configuration failures while rate limits may retry", () => {
  const quota = classifyFailure({ status: 429, error: { code: "insufficient_quota", message: "Billing quota exceeded" } }, "model");
  assert.equal(quota.code, "MODEL_QUOTA");
  assert.equal(quota.retryable, false);
  assert.equal(quota.recovery, "configure");
  const bodyQuota = classifyFailure({ statusCode: 429, responseBody: '{"error":{"code":"insufficient_quota"}}' }, "model");
  assert.equal(bodyQuota.code, "MODEL_QUOTA");
  const rate = classifyFailure({ statusCode: 429, message: "Too many requests" }, "model");
  assert.equal(rate.code, "MODEL_RATE_LIMIT");
  assert.equal(rate.retryable, true);
});

test("classifies common API, tool, document, storage and cancellation failures", () => {
  assert.equal(classifyFailure({ status: 401 }, "model").code, "MODEL_AUTH");
  assert.equal(classifyFailure({ response: { status: 503 } }, "model").code, "MODEL_UNAVAILABLE");
  assert.equal(classifyFailure({ status: 504 }, "model").code, "MODEL_TIMEOUT");
  assert.equal(classifyFailure({ status: 404 }, "kb").code, "KB_DOC_MISSING");
  assert.equal(classifyFailure(new Error("index unavailable"), "kb").code, "KB_UNAVAILABLE");
  assert.equal(classifyFailure({ code: "ENOENT" }, "tool").code, "TOOL_MISSING");
  assert.equal(classifyFailure(new Error("timed out"), "tool").code, "TOOL_TIMEOUT");
  assert.equal(classifyFailure(new Error("exit code 1"), "tool").code, "TOOL_FAILED");
  assert.equal(classifyFailure(new Error("disk full"), "storage").code, "STORAGE_FAILED");
  assert.equal(classifyFailure({ name: "AbortError" }, "model").code, "USER_CANCELLED");
  assert.equal(classifyFailure(new Error("Time budget exhausted"), "model").code, "BUDGET_TIME");
  assert.equal(classifyFailure(new Error("Token budget exhausted"), "agent").code, "BUDGET_TOKENS");
  assert.equal(classifyFailure(new Error("unrecognized"), "agent").code, "UNKNOWN");
});

test("unobserved layers stay unknown and separate goals cannot share traces", () => {
  const monitor = new HealthMonitor({ goalId: "goal-a" });
  assert.equal(monitor.snapshot().observedEvents, 0);
  for (const layer of HEALTH_LAYERS) assert.equal(monitor.snapshot().layers[layer].status, "unknown");
  assert.throws(() => monitor.record(event("wrong", { goalId: "goal-b" })), /another goal/);
  monitor.record(event("start", { branchId: "red", agentId: "researcher", nodeId: "n1" }));
  assert.equal(monitor.snapshot().layers.model.status, "running");
  assert.equal(monitor.snapshot().layers.kb.status, "unknown");
  const other = new HealthMonitor({ goalId: "goal-b" });
  assert.equal(other.readHistory().length, 0);
});

test("aggregates concurrent branches and preserves correlation and duration", () => {
  const monitor = new HealthMonitor({ goalId: "goal-a" });
  monitor.record(event("red-failure", { branchId: "red", agentId: "r", nodeId: "n1", status: "failed", code: "MODEL_TIMEOUT", timestamp: 2 }));
  monitor.record(event("blue-ok", { branchId: "blue", agentId: "b", nodeId: "n1", status: "healthy", timestamp: 3 }));
  assert.equal(monitor.snapshot().layers.model.status, "failed");
  monitor.record(event("red-recovery", { branchId: "red", agentId: "r", nodeId: "n1", status: "healthy", timestamp: 4, correlationId: "red-failure", durationMs: 15 }));
  assert.equal(monitor.snapshot().layers.model.status, "healthy");
  assert.equal(monitor.snapshot().layers.model.lastEvent?.correlationId, "red-failure");
  assert.equal(monitor.snapshot().layers.model.lastEvent?.durationMs, 15);
  monitor.record(event("delayed-start", { branchId: "red", agentId: "r", nodeId: "n1", status: "running", timestamp: 1 }));
  assert.equal(monitor.snapshot().layers.model.status, "healthy");
});

test("retains bounded immutable history with cumulative per-layer counts", () => {
  const monitor = new HealthMonitor({ goalId: "goal-a", maxHistory: 2 });
  const first = event("m1", { layer: "kb", status: "healthy" });
  assert.equal(monitor.record(first), true);
  assert.equal(monitor.record(first), false);
  monitor.record(event("m2", { timestamp: 2 }));
  monitor.record(event("m3", { timestamp: 3, status: "healthy" }));
  assert.deepEqual(monitor.readHistory().map(item => item.eventId), ["m2", "m3"]);
  assert.equal(monitor.snapshot().observedEvents, 3);
  assert.equal(monitor.snapshot().retainedEvents, 2);
  assert.equal(monitor.snapshot().layers.kb.observedEvents, 1);
  assert.equal(monitor.snapshot().layers.kb.status, "healthy");
  assert.ok(Object.isFrozen(monitor.readHistory()));
  assert.ok(Object.isFrozen(monitor.readHistory()[0]));
  assert.ok(Object.isFrozen(monitor.snapshot().layers));
  assert.throws(() => monitor.record(event("bad", { durationMs: -1 })), /duration/);
});
