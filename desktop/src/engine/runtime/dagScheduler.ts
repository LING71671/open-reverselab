export type DagNodeStatus = "queued" | "running" | "succeeded" | "failed" | "cancelled";
export type DagDependencyPolicy = "allSucceeded" | "allSettled";

export interface DagNodeResult<T> {
  readonly id: string;
  readonly parentIds: readonly string[];
  readonly resourceKeys: readonly string[];
  readonly status: DagNodeStatus;
  readonly value?: T;
  readonly error?: unknown;
  readonly cancellationReason?: unknown;
  readonly cancellationRequested?: boolean;
  readonly startedAt?: number;
  readonly finishedAt?: number;
}

export interface DagNodeContext<T> {
  readonly nodeId: string;
  readonly signal: AbortSignal;
  /** Contains every direct parent, including failures and cancellations at a join. */
  readonly parentResults: ReadonlyMap<string, DagNodeResult<T>>;
}

export interface DagNode<T> {
  readonly id: string;
  readonly parentIds?: readonly string[];
  readonly dependencyPolicy?: DagDependencyPolicy;
  /** Keys are exclusive within the injected resource pool until the runner settles. */
  readonly resourceKeys?: readonly string[];
  readonly run: (context: DagNodeContext<T>) => Promise<T>;
}

export interface DagSchedulerOptions<T> {
  readonly concurrency?: number;
  readonly signal?: AbortSignal;
  readonly onNodeUpdate?: (result: DagNodeResult<T>) => void;
  /** Share one pool across goals to serialize access to the same device or file. */
  readonly resourcePool?: DagResourcePool;
}

export interface DagRunResult<T> {
  readonly status: "succeeded" | "failed" | "cancelled";
  readonly nodes: ReadonlyMap<string, DagNodeResult<T>>;
  /** Observer exceptions do not turn successful tool executions into failures. */
  readonly observerErrors: readonly unknown[];
}

type PreparedNode<T> = DagNode<T> & {
  readonly parentIds: readonly string[];
  readonly resourceKeys: readonly string[];
  readonly dependencyPolicy: DagDependencyPolicy;
};

function isTerminal(status: DagNodeStatus): boolean {
  return status === "succeeded" || status === "failed" || status === "cancelled";
}

/** Atomic, in-process resource ownership. It has no knowledge of goals or tools. */
export class DagResourcePool {
  private readonly owners = new Map<string, symbol>();
  private readonly listeners = new Set<() => void>();

  public tryAcquire(keys: readonly string[], owner: symbol): boolean {
    if (keys.some((key) => this.owners.has(key) && this.owners.get(key) !== owner)) return false;
    for (const key of keys) this.owners.set(key, owner);
    return true;
  }

  public release(owner: symbol): void {
    let changed = false;
    for (const [key, holder] of this.owners) {
      if (holder === owner) { this.owners.delete(key); changed = true; }
    }
    if (changed) for (const listener of this.listeners) {
      try { listener(); } catch { /* One subscriber cannot prevent other goals from waking. */ }
    }
  }

  public subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}

/**
 * Runs a validated, immutable DAG once. It owns dependency/concurrency decisions,
 * while runners own models, tools, budgets, evidence, and cooperative cancellation.
 */
export class DagScheduler<T> {
  private readonly nodes = new Map<string, PreparedNode<T>>();
  private readonly results = new Map<string, DagNodeResult<T>>();
  private readonly children = new Map<string, string[]>();
  private readonly controllers = new Map<string, AbortController>();
  private readonly resourcePool: DagResourcePool;
  private readonly observerErrors: unknown[] = [];
  private readonly concurrency: number;
  private readonly options: DagSchedulerOptions<T>;
  private active = 0;
  private pumpScheduled = false;
  private globallyCancelled = false;
  private finished = false;
  private runPromise?: Promise<DagRunResult<T>>;
  private resolveRun?: (result: DagRunResult<T>) => void;
  private detachAbort?: () => void;
  private detachResources?: () => void;

  constructor(nodes: readonly DagNode<T>[], options: DagSchedulerOptions<T> = {}) {
    this.options = { ...options };
    this.resourcePool = options.resourcePool ?? new DagResourcePool();
    this.concurrency = options.concurrency ?? 2;
    if (!Number.isInteger(this.concurrency) || this.concurrency < 1) {
      throw new Error("DAG concurrency must be a positive integer");
    }
    for (const node of nodes) {
      if (typeof node.id !== "string" || !node.id.trim()) throw new Error("DAG node ID must not be empty");
      if (this.nodes.has(node.id)) throw new Error(`Duplicate DAG node ID: ${node.id}`);
      if (typeof node.run !== "function") throw new Error(`DAG node has no runner: ${node.id}`);
      const parentIds = Object.freeze([...(node.parentIds ?? [])]);
      if (new Set(parentIds).size !== parentIds.length) throw new Error(`Duplicate dependency for DAG node: ${node.id}`);
      const dependencyPolicy = node.dependencyPolicy ?? "allSucceeded";
      if (dependencyPolicy !== "allSucceeded" && dependencyPolicy !== "allSettled") {
        throw new Error(`Invalid dependency policy for DAG node: ${node.id}`);
      }
      const resourceKeys = Object.freeze([...new Set(node.resourceKeys ?? [])]);
      if (resourceKeys.some((key) => typeof key !== "string" || !key.trim())) {
        throw new Error(`Invalid resource key for DAG node: ${node.id}`);
      }
      this.nodes.set(node.id, Object.freeze({ ...node, parentIds, resourceKeys, dependencyPolicy }));
      this.children.set(node.id, []);
      this.results.set(node.id, Object.freeze({ id: node.id, parentIds, resourceKeys, status: "queued" }));
    }
    this.validateDependencies();
  }

  /** A second call returns the original run; no node is executed twice. */
  public run(): Promise<DagRunResult<T>> {
    if (this.runPromise) return this.runPromise;
    this.runPromise = new Promise((resolve) => { this.resolveRun = resolve; });
    this.detachResources = this.resourcePool.subscribe(() => this.schedulePump());
    for (const result of this.results.values()) this.notify(result);
    const signal = this.options.signal;
    if (signal) {
      const abort = () => this.cancel(signal.reason);
      if (signal.aborted) abort();
      else {
        signal.addEventListener("abort", abort, { once: true });
        this.detachAbort = () => signal.removeEventListener("abort", abort);
      }
    }
    this.schedulePump();
    return this.runPromise;
  }

  public getSnapshot(): ReadonlyMap<string, DagNodeResult<T>> {
    return new Map(this.results);
  }

  public cancel(reason: unknown = "DAG run cancelled"): void {
    if (this.finished) return;
    this.globallyCancelled = true;
    for (const id of this.nodes.keys()) this.cancelNode(id, reason);
    this.schedulePump();
  }

  /** Cancels this node; dependency policies decide what its descendants do. */
  public cancelNode(id: string, reason: unknown = "DAG node cancelled"): boolean {
    const current = this.results.get(id);
    if (!current) throw new Error(`Unknown DAG node: ${id}`);
    if (isTerminal(current.status) || current.cancellationRequested) return false;
    if (current.status === "running") {
      this.update(id, { cancellationRequested: true, cancellationReason: reason });
      this.controllers.get(id)?.abort(reason);
    } else {
      this.update(id, { status: "cancelled", cancellationReason: reason, finishedAt: Date.now() });
    }
    this.schedulePump();
    return true;
  }

  /**
   * Cancels a branch, including active descendants. An allSettled join is a
   * boundary: it remains available to aggregate this branch's cancelled result.
   */
  public cancelBranch(id: string, reason: unknown = "DAG branch cancelled"): number {
    if (!this.nodes.has(id)) throw new Error(`Unknown DAG node: ${id}`);
    const pending = [id];
    const visited = new Set<string>();
    let cancelled = 0;
    while (pending.length) {
      const current = pending.pop()!;
      if (visited.has(current)) continue;
      visited.add(current);
      if (this.cancelNode(current, reason)) cancelled++;
      for (const child of this.children.get(current)!) {
        if (this.nodes.get(child)!.dependencyPolicy !== "allSettled") pending.push(child);
      }
    }
    return cancelled;
  }

  private validateDependencies(): void {
    const remaining = new Map<string, number>();
    for (const node of this.nodes.values()) {
      remaining.set(node.id, node.parentIds.length);
      for (const parentId of node.parentIds) {
        const siblings = this.children.get(parentId);
        if (!siblings) throw new Error(`Missing DAG dependency ${parentId} for node ${node.id}`);
        siblings.push(node.id);
      }
    }
    const ready = [...remaining].filter(([, count]) => count === 0).map(([id]) => id);
    let visited = 0;
    for (let index = 0; index < ready.length; index++) {
      visited++;
      for (const child of this.children.get(ready[index])!) {
        const count = remaining.get(child)! - 1;
        remaining.set(child, count);
        if (count === 0) ready.push(child);
      }
    }
    if (visited !== this.nodes.size) throw new Error("DAG contains a dependency cycle");
  }

  private notify(result: DagNodeResult<T>): void {
    try { this.options.onNodeUpdate?.(result); }
    catch (error) { this.observerErrors.push(error); }
  }

  private update(id: string, patch: Partial<DagNodeResult<T>>): void {
    const result = Object.freeze({ ...this.results.get(id)!, ...patch });
    this.results.set(id, result);
    this.notify(result);
  }

  private schedulePump(): void {
    if (!this.runPromise || this.finished || this.pumpScheduled) return;
    this.pumpScheduled = true;
    queueMicrotask(() => {
      this.pumpScheduled = false;
      this.pump();
    });
  }

  private pump(): void {
    if (this.finished) return;
    // Repeat when dependencies are cancelled during this pass, irrespective of
    // declaration order. Actual runner completions schedule their own pass.
    let dependencyCancelled: boolean;
    do {
      dependencyCancelled = false;
      for (const node of this.nodes.values()) {
        if (this.results.get(node.id)!.status !== "queued") continue;
        const parents = node.parentIds.map((id) => this.results.get(id)!);
        if (parents.some((parent) => !isTerminal(parent.status))) continue;
        if (node.dependencyPolicy === "allSucceeded" && parents.some((parent) => parent.status !== "succeeded")) {
          const unsuccessful = parents.filter((parent) => parent.status !== "succeeded").map((parent) => `${parent.id}:${parent.status}`);
          this.cancelNode(node.id, `Required dependencies did not succeed: ${unsuccessful.join(", ")}`);
          dependencyCancelled = true;
          continue;
        }
        if (this.active >= this.concurrency) continue;
        this.start(node);
      }
    } while (dependencyCancelled);
    if (this.active === 0 && [...this.results.values()].every((result) => isTerminal(result.status))) {
      this.finished = true;
      this.detachAbort?.();
      this.detachResources?.();
      const results = [...this.results.values()];
      const status = this.globallyCancelled ? "cancelled"
        : results.some((result) => result.status === "failed") ? "failed"
        : results.some((result) => result.status === "cancelled") ? "cancelled" : "succeeded";
      this.resolveRun?.({ status, nodes: this.getSnapshot(), observerErrors: Object.freeze([...this.observerErrors]) });
    }
  }

  private start(node: PreparedNode<T>): void {
    const resourceOwner = Symbol(node.id);
    if (!this.resourcePool.tryAcquire(node.resourceKeys, resourceOwner)) return;
    const controller = new AbortController();
    this.controllers.set(node.id, controller);
    this.active++;
    this.update(node.id, { status: "running", startedAt: Date.now() });
    const parentResults = new Map(node.parentIds.map((id) => [id, this.results.get(id)!]));
    void (async () => {
      try {
        if (controller.signal.aborted) throw controller.signal.reason;
        const value = await node.run({ nodeId: node.id, signal: controller.signal, parentResults });
        if (controller.signal.aborted) {
          this.update(node.id, { status: "cancelled", cancellationReason: controller.signal.reason, finishedAt: Date.now() });
        } else {
          this.update(node.id, { status: "succeeded", value, finishedAt: Date.now() });
        }
      } catch (error) {
        this.update(node.id, controller.signal.aborted
          ? { status: "cancelled", error, cancellationReason: controller.signal.reason, finishedAt: Date.now() }
          : { status: "failed", error, finishedAt: Date.now() });
      } finally {
        // Aborting a signal does not prove a tool has stopped. Keep its slot and
        // resource locks until the runner actually resolves or rejects.
        this.active--;
        this.controllers.delete(node.id);
        this.resourcePool.release(resourceOwner);
        this.schedulePump();
      }
    })();
  }
}
