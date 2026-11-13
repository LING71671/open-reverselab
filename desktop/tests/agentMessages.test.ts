import assert from "node:assert/strict";
import test from "node:test";
import { AgentMessageBus } from "../src/engine/runtime/agentMessages.ts";
import type { AgentMessage } from "../src/engine/runtime/agentMessages.ts";

const makeBus = (options = {}) => new AgentMessageBus({
  goalId: "goal-a", agents: ["red", "blue", "coordinator"], ...options,
});
const message = (id: string, overrides: Partial<AgentMessage> = {}): AgentMessage => ({
  id, goalId: "goal-a", from: "red", to: "blue", type: "evidence",
  payload: { content: "Observed branch", evidenceRefs: [{ id: "evidence-1", path: "exports/trace.json" }] },
  ...overrides,
});

test("routes only to the addressed registered agent and isolates goals", () => {
  const bus = makeBus();
  const other = makeBus({ goalId: "goal-b" });
  const delivered: string[] = [];
  bus.subscribe("red", () => delivered.push("red"));
  bus.subscribe("blue", () => delivered.push("blue"));
  assert.equal(bus.dispatch(message("m1")), true);
  assert.deepEqual(delivered, ["blue"]);
  assert.equal(bus.readInbox("red").length, 0);
  assert.equal(other.readInbox("blue").length, 0);
  assert.throws(() => other.dispatch(message("m1")), /another goal/);
  assert.throws(() => bus.dispatch(message("m2", { from: "unknown" })), /not registered/);
  assert.throws(() => bus.dispatch(message("m2", { to: "unknown" })), /not registered/);
  assert.throws(() => bus.subscribe("unknown", () => {}), /not registered/);
  assert.throws(() => bus.readInbox("unknown"), /not registered/);
});

test("correlated replies inherit hops and cannot reset the conversation budget", () => {
  const bus = makeBus({ maxHops: 2 });
  bus.dispatch(message("q", { type: "question" }));
  bus.dispatch(message("a", { type: "answer", from: "blue", to: "red", correlationId: "q" }));
  assert.equal(bus.readInbox("red")[0].correlationId, "q");
  assert.equal(bus.readInbox("red")[0].hopCount, 1);
  assert.throws(() => bus.dispatch(message("reset", { correlationId: "a", hopCount: 0 })), /hop/);
  bus.dispatch(message("followup", { correlationId: "a" }));
  assert.throws(() => bus.dispatch(message("loop", { correlationId: "followup" })), /hop/);
  assert.throws(() => bus.dispatch(message("orphan", { correlationId: "other-goal-id" })), /Correlation/);
});

test("deduplicates accepted IDs even when bounded history has evicted them", () => {
  const bus = makeBus({ maxHistory: 1, maxInbox: 1 });
  let count = 0;
  bus.subscribe("blue", () => count++);
  bus.dispatch(message("first"));
  bus.dispatch(message("second"));
  assert.equal(bus.dispatch(message("first")), false);
  assert.equal(count, 2);
  assert.deepEqual(bus.readHistory().map((entry) => entry.id), ["second"]);
  assert.deepEqual(bus.readInbox("blue").map((entry) => entry.id), ["second"]);
});

test("unsubscribe is independent and idempotent without deleting mailbox contents", () => {
  const bus = makeBus();
  let count = 0;
  const handler = () => count++;
  const unsubscribe = bus.subscribe("blue", handler);
  const second = bus.subscribe("blue", handler);
  unsubscribe();
  unsubscribe();
  bus.dispatch(message("m1"));
  assert.equal(count, 1);
  second();
  bus.dispatch(message("m2"));
  assert.equal(count, 1);
  assert.equal(bus.readInbox("blue").length, 2);
  bus.subscribe("blue", handler);
  unsubscribe();
  second();
  bus.dispatch(message("m3"));
  assert.equal(count, 2);
});

test("copies and freezes payloads so peers cannot share mutable evidence", () => {
  const bus = makeBus();
  const payload = { content: "initial", evidenceRefs: [{ id: "e1", summary: "original" }] };
  bus.dispatch(message("m1", { payload }));
  payload.content = "modified";
  payload.evidenceRefs[0].summary = "changed";
  const stored = bus.readInbox("blue")[0];
  assert.equal(stored.payload.content, "initial");
  assert.equal(stored.payload.evidenceRefs?.[0].summary, "original");
  assert.ok(Object.isFrozen(stored));
  assert.ok(Object.isFrozen(stored.payload));
  assert.ok(Object.isFrozen(stored.payload.evidenceRefs));
  assert.ok(Object.isFrozen(stored.payload.evidenceRefs?.[0]));
  assert.ok(Object.isFrozen(bus.readHistory()));
});

test("bounded total delivery stops ping-pong that invents uncorrelated message IDs", () => {
  const bus = makeBus({ maxMessages: 5, maxInbox: 2, maxHistory: 3 });
  let index = 0;
  let depth = 0;
  let maximumDepth = 0;
  const reply = (incoming: AgentMessage) => {
    depth++;
    maximumDepth = Math.max(maximumDepth, depth);
    try {
      bus.dispatch(message(`reply-${++index}`, { from: incoming.to, to: incoming.from }));
    } finally {
      depth--;
    }
  };
  bus.subscribe("red", reply);
  bus.subscribe("blue", reply);
  assert.throws(() => bus.dispatch(message("start")), /budget exhausted/);
  assert.equal(maximumDepth, 1);
  assert.equal(bus.readHistory().length, 3);
  assert.equal(bus.readInbox("red").length, 2);
  assert.equal(bus.readInbox("blue").length, 2);
  assert.equal(bus.dispatch(message("start")), false);
});

test("a failing subscriber does not prevent other subscribers receiving accepted messages", () => {
  const bus = makeBus();
  let delivered = false;
  bus.subscribe("blue", () => { throw new Error("Subscriber failed"); });
  bus.subscribe("blue", () => { delivered = true; });
  assert.throws(() => bus.dispatch(message("m1")), /Subscriber failed/);
  assert.equal(delivered, true);
});

test("rejects invalid limits and negative or fractional hop values", () => {
  assert.throws(() => makeBus({ maxHistory: 0 }), /positive integer/);
  assert.throws(() => makeBus({ maxMessages: Number.POSITIVE_INFINITY }), /positive integer/);
  const bus = makeBus({ maxHops: 0 });
  assert.throws(() => bus.dispatch(message("m1", { hopCount: -1 })), /hop/);
  assert.throws(() => bus.dispatch(message("m1", { hopCount: 0.5 })), /hop/);
  assert.equal(bus.dispatch(message("m1")), true);
  assert.throws(() => bus.dispatch(message("m2", { correlationId: "m1" })), /hop/);
});
