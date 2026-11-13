export type AgentMessageType = "evidence" | "question" | "answer" | "blocked" | "result";

export interface AgentEvidenceReference {
  readonly id: string;
  readonly nodeId?: string;
  readonly path?: string;
  readonly summary?: string;
}

export interface AgentMessagePayload {
  readonly content: string;
  readonly evidenceRefs?: readonly AgentEvidenceReference[];
}

export interface AgentMessage {
  readonly id: string;
  readonly goalId: string;
  readonly from: string;
  readonly to: string;
  readonly type: AgentMessageType;
  readonly correlationId?: string;
  readonly hopCount?: number;
  readonly payload: AgentMessagePayload;
}

export interface AgentMessageBusOptions {
  readonly goalId: string;
  readonly agents: readonly string[];
  readonly maxHistory?: number;
  readonly maxInbox?: number;
  readonly maxMessages?: number;
  readonly maxHops?: number;
}

type MessageHandler = (message: AgentMessage) => void;

const MESSAGE_TYPES: ReadonlySet<string> = new Set([
  "evidence", "question", "answer", "blocked", "result",
]);

function positiveLimit(value: number, name: string, allowZero = false): number {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1)) {
    throw new Error(`${name} must be ${allowZero ? "a non-negative" : "a positive"} integer`);
  }
  return value;
}

function requireId(value: string, name: string): void {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${name} is required`);
}

/** An in-memory mailbox shared only by the registered agents of one goal. */
export class AgentMessageBus {
  readonly goalId: string;
  private readonly agents: ReadonlySet<string>;
  private readonly maxHistory: number;
  private readonly maxInbox: number;
  private readonly maxMessages: number;
  private readonly maxHops: number;
  // Retain bounded receipt metadata even after display history expires, so old
  // message IDs cannot be replayed and correlations keep their original hop count.
  private readonly receipts = new Map<string, number>();
  private readonly inboxes = new Map<string, AgentMessage[]>();
  private readonly handlers = new Map<string, Set<MessageHandler>>();
  private readonly history: AgentMessage[] = [];
  private readonly pending: AgentMessage[] = [];
  private delivering = false;

  constructor(options: AgentMessageBusOptions) {
    requireId(options.goalId, "goalId");
    if (!options.agents.length) throw new Error("At least one registered agent is required");
    for (const agent of options.agents) requireId(agent, "agent ID");
    this.goalId = options.goalId;
    this.agents = new Set(options.agents);
    this.maxHistory = positiveLimit(options.maxHistory ?? 128, "maxHistory");
    this.maxInbox = positiveLimit(options.maxInbox ?? 64, "maxInbox");
    this.maxMessages = positiveLimit(options.maxMessages ?? 512, "maxMessages");
    this.maxHops = positiveLimit(options.maxHops ?? 8, "maxHops", true);
  }

  private requireAgent(agentId: string): void {
    if (!this.agents.has(agentId)) throw new Error(`Agent is not registered: ${agentId}`);
  }

  subscribe(agentId: string, handler: MessageHandler): () => void {
    this.requireAgent(agentId);
    const subscribers = this.handlers.get(agentId) ?? new Set<MessageHandler>();
    // A wrapper gives each subscription an independent, idempotent unsubscribe.
    const subscription: MessageHandler = (message) => handler(message);
    subscribers.add(subscription);
    this.handlers.set(agentId, subscribers);
    return () => {
      subscribers.delete(subscription);
      if (!subscribers.size && this.handlers.get(agentId) === subscribers) {
        this.handlers.delete(agentId);
      }
    };
  }

  readInbox(agentId: string): readonly AgentMessage[] {
    this.requireAgent(agentId);
    return Object.freeze([...(this.inboxes.get(agentId) ?? [])]);
  }

  readHistory(): readonly AgentMessage[] {
    return Object.freeze([...this.history]);
  }

  /** Returns false for an already accepted ID; invalid or exhausted messages throw. */
  dispatch(message: AgentMessage): boolean {
    if (message.goalId !== this.goalId) throw new Error("Message belongs to another goal");
    this.requireAgent(message.from);
    this.requireAgent(message.to);
    requireId(message.id, "message ID");
    if (this.receipts.has(message.id)) return false;
    if (this.receipts.size >= this.maxMessages) throw new Error("Goal message budget exhausted");
    if (!MESSAGE_TYPES.has(message.type)) throw new Error("Unknown message type");
    if (!message.payload || typeof message.payload.content !== "string") {
      throw new Error("Message payload must contain text content");
    }

    let minimumHops = 0;
    if (message.correlationId !== undefined) {
      const parentHops = this.receipts.get(message.correlationId);
      if (parentHops === undefined) throw new Error("Correlation must reference an accepted message in this goal");
      minimumHops = parentHops + 1;
    }
    const hops = message.hopCount ?? minimumHops;
    if (!Number.isSafeInteger(hops) || hops < minimumHops || hops > this.maxHops) {
      throw new Error("Message hop limit exceeded or hop count invalid");
    }
    const evidenceRefs = message.payload.evidenceRefs?.map((reference) => {
      requireId(reference.id, "evidence ID");
      if ((reference.nodeId !== undefined && typeof reference.nodeId !== "string") ||
          (reference.path !== undefined && typeof reference.path !== "string") ||
          (reference.summary !== undefined && typeof reference.summary !== "string")) {
        throw new Error("Evidence references must contain string paths and summaries");
      }
      return Object.freeze({ id: reference.id, nodeId: reference.nodeId, path: reference.path, summary: reference.summary });
    });
    const accepted: AgentMessage = Object.freeze({
      id: message.id,
      goalId: this.goalId,
      from: message.from,
      to: message.to,
      type: message.type,
      correlationId: message.correlationId,
      hopCount: hops,
      payload: Object.freeze({
        content: message.payload.content,
        evidenceRefs: evidenceRefs && Object.freeze(evidenceRefs),
      }),
    });
    this.receipts.set(accepted.id, hops);
    this.history.push(accepted);
    if (this.history.length > this.maxHistory) this.history.shift();
    const inbox = this.inboxes.get(accepted.to) ?? [];
    inbox.push(accepted);
    if (inbox.length > this.maxInbox) inbox.shift();
    this.inboxes.set(accepted.to, inbox);
    this.pending.push(accepted);
    this.deliverPending();
    return true;
  }

  private deliverPending(): void {
    if (this.delivering) return;
    this.delivering = true;
    const errors: unknown[] = [];
    try {
      // Reentrant dispatch queues the reply instead of recursively invoking peers.
      while (this.pending.length) {
        const message = this.pending.shift()!;
        for (const handler of [...(this.handlers.get(message.to) ?? [])]) {
          try {
            handler(message);
          } catch (error) {
            errors.push(error);
          }
        }
      }
    } finally {
      this.delivering = false;
    }
    // A faulty subscriber must not prevent delivery to other subscribers, and its
    // failure must remain visible to the caller that started this dispatch batch.
    if (errors.length) throw errors[0];
  }
}
