import type { SessionItem, HarnessChatMessage, GraphStep, Deliverables, StageDiagnostic, DiscoveredSample, LogEntry, SecurityTrack, RunBudget, RunProgress, PipelineCallbacks } from "../../core";
import type { HealthEvent } from "../../core/contracts/health";

export interface GoalRecord {
  messages: HarnessChatMessage[];
  steps: GraphStep[];
  logs: LogEntry[];
  diagnostics: Record<string, StageDiagnostic>;
  samples: DiscoveredSample[];
  deliverables: Deliverables | null;
  progress?: RunProgress;
  healthEvents?: HealthEvent[];
}
export interface GoalSnapshot { sessions: SessionItem[]; records: Record<string, GoalRecord>; persistenceError?: string }
export interface GoalRequest { id: string; target: string; objective: string; track: SecurityTrack; budget?: RunBudget; revision?: number; history?: Array<{ role: string; content: string }> }
export type GoalRunner = (request: GoalRequest, callbacks: PipelineCallbacks, signal: AbortSignal) => Promise<unknown>;
export interface GoalStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void | Promise<void>;
  removeItem(key: string): void;
}
const emptyRecord = (): GoalRecord => ({ messages: [], steps: [], logs: [], diagnostics: {}, samples: [], deliverables: null });
const trackValid = (value: unknown): value is SecurityTrack => value === "red" || value === "blue" || value === "both";
const uniqueId = () => `goal-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

/** Owns task scheduling and persistence. It has no React, browser, model or tool dependency. */
export class GoalManager {
  private snapshot: GoalSnapshot = { sessions: [], records: {} };
  private listeners = new Set<() => void>();
  private healthListeners = new Set<(event: HealthEvent) => void>();
  private queue: GoalRequest[] = [];
  private controllers = new Map<string, AbortController>();
  private requests = new Map<string, GoalRequest>();
  private adjustments = new Map<string, GoalRequest>();
  private started = new Map<string, number>();
  private saveTimer?: ReturnType<typeof setTimeout>;
  private saveRevision = 0;
  /** Omit concurrency to start every submitted Goal without an application limit. */
  constructor(private runner: GoalRunner, private storage?: GoalStorage, private concurrency?: number) {
    if (concurrency !== undefined && (!Number.isInteger(concurrency) || concurrency < 1)) throw new Error("Invalid goal concurrency");
    try {
      const data = JSON.parse(storage?.getItem("reverselab_goals_v2") || "null") as GoalSnapshot | null;
      if (data && Array.isArray(data.sessions) && data.records) {
        this.snapshot = {
          sessions: data.sessions.filter(s => s && typeof s.id === "string" && trackValid(s.track)).map(s => ({ ...s, status: s.status === "running" || s.status === "queued" ? "cancelled" : s.status })),
          records: data.records,
        };
        for (const session of this.snapshot.sessions) {
          const record = this.snapshot.records[session.id];
          if (!record) this.snapshot.records[session.id] = emptyRecord();
          else {
            record.messages = (record.messages || []).map(m => ({ ...m, isRunning: false, adjustment: m.adjustment?.status === "pending" ? { ...m.adjustment, status: "cancelled" } : m.adjustment }));
            if (record.progress?.status === "running") record.progress = { ...record.progress, status: "cancelled", reason: "应用关闭，运行已中断" };
            record.steps = (record.steps || []).map(step => step.status === "running" || step.status === "pending" ? { ...step, status: "failed", detail: "应用关闭，运行已中断" } : step);
            const traces = new Map<string, HealthEvent>();
            for (const event of record.healthEvents || []) traces.set(JSON.stringify([event.layer, event.branchId, event.agentId, event.nodeId]), event);
            const stopped = [...traces.values()].filter(event => event.status === "running").map(event => ({ ...event, eventId: `${event.eventId}:interrupted`, status: "cancelled" as const, timestamp: Date.now(), code: "USER_CANCELLED" as const, reason: "应用关闭，运行已中断" }));
            if (stopped.length) record.healthEvents = [...(record.healthEvents || []), ...stopped].slice(-256);
          }
        }
      } else this.importLegacy();
    } catch { /* A damaged saved record must not prevent starting a new goal. */ }
  }
  private importLegacy() {
    const list = JSON.parse(this.storage?.getItem("reverselab_sessions") || "[]");
    if (!Array.isArray(list)) return;
    for (const old of list) {
      if (!old || typeof old.id !== "string" || old.id === "sess-revo-pro-verified") continue;
      this.snapshot.sessions.push({ ...old, track: trackValid(old.track) ? old.track : "both", status: old.status === "running" ? "cancelled" : old.status });
      try {
        const record = JSON.parse(this.storage?.getItem(`reverselab_session_data_${old.id}`) || "{}");
        this.snapshot.records[old.id] = { ...emptyRecord(), messages: (record.messages || []).map((m: HarnessChatMessage) => ({ ...m, isRunning: false })), steps: record.steps || [], logs: record.logs || [], diagnostics: record.activeDiagnostics || {}, samples: record.discoveredSamples || [], deliverables: record.deliverables || null };
      } catch { this.snapshot.records[old.id] = emptyRecord(); }
    }
  }
  getSnapshot = () => this.snapshot;
  setPersistenceError = (persistenceError?: string) => {
    if (persistenceError === this.snapshot.persistenceError) return;
    this.snapshot = { ...this.snapshot, persistenceError };
    this.listeners.forEach(listener => listener());
  };
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener); }; };
  /** Only accepted live events are published; restoring or reading history is local. */
  subscribeHealth = (listener: (event: HealthEvent) => void) => { this.healthListeners.add(listener); return () => { this.healthListeners.delete(listener); }; };
  flush = () => {
    if (this.saveTimer) clearTimeout(this.saveTimer);
    if (!this.storage) return;
    const revision = ++this.saveRevision;
    const saved = (error?: unknown) => {
      if (revision === this.saveRevision) this.setPersistenceError(error ? error instanceof Error ? error.message : String(error) : undefined);
    };
    try {
      const result = this.storage.setItem("reverselab_goals_v2", JSON.stringify({ sessions: this.snapshot.sessions, records: this.snapshot.records }));
      if (result && typeof result.then === "function") void result.then(() => saved(), saved);
      else saved();
    } catch (error) { saved(error); }
  };
  private emit() {
    this.snapshot = { ...this.snapshot };
    this.listeners.forEach(listener => listener());
    if (this.saveTimer) clearTimeout(this.saveTimer);
    this.saveTimer = setTimeout(this.flush, 180);
  }
  private update(id: string, change: (record: GoalRecord) => GoalRecord) {
    if (!this.snapshot.records[id]) return;
    this.snapshot.records = { ...this.snapshot.records, [id]: change(this.snapshot.records[id]) };
    this.emit();
  }
  private status(id: string, status: SessionItem["status"]) {
    this.snapshot.sessions = this.snapshot.sessions.map(s => s.id === id ? { ...s, status } : s);
    this.emit();
  }
  private log(id: string, level: LogEntry["level"], message: string, payload?: unknown) {
    this.update(id, record => ({ ...record, logs: [...record.logs, { id: uniqueId(), timestamp: Date.now(), level, agentId: id, message, payload }].slice(-1000) }));
  }
  create(track: SecurityTrack): string {
    const id = uniqueId();
    this.snapshot.sessions = [{ id, track, target: "", title: "新 Goal", time: new Date().toISOString(), status: "idle" }, ...this.snapshot.sessions];
    this.snapshot.records = { ...this.snapshot.records, [id]: emptyRecord() };
    this.emit();
    return id;
  }
  submit(target: string, objective: string, track: SecurityTrack, budget?: RunBudget, draftId?: string): string {
    if (!target.trim() || !objective.trim()) throw new Error("请填写 target 和 Goal");
    const draft = this.snapshot.sessions.find(s => s.id === draftId && s.status === "idle" && s.track === track);
    const id = draft?.id || this.create(track);
    const request: GoalRequest = Object.freeze({ id, target: target.trim(), objective: objective.trim(), track, budget: budget ? Object.freeze({ ...budget }) : undefined });
    this.requests.set(id, request);
    this.snapshot.sessions = this.snapshot.sessions.map(s => s.id === id ? { ...s, target: request.target, title: s.customTitle ? s.title : "分析任务", status: "queued" } : s);
    this.snapshot.records = { ...this.snapshot.records, [id]: { ...emptyRecord(), messages: [{ id: `${id}-user`, role: "user", content: objective, target, timestamp: Date.now() }] } };
    this.queue.push(request);
    this.emit();
    this.pump();
    return id;
  }
  steer(id: string, instruction: string) {
    const text = instruction.trim();
    if (!text) return;
    const session = this.snapshot.sessions.find(item => item.id === id);
    const previous = this.adjustments.get(id) || this.requests.get(id);
    if (!previous || !session || !["running", "queued"].includes(session.status)) throw new Error("任务已结束，请创建新的 Goal");
    const revision = (previous.revision || 0) + 1;
    const next: GoalRequest = Object.freeze({ ...previous, revision, objective: `${previous.objective}\n\n用户补充要求 ${revision}（与前文冲突时以较新的要求为准）：\n${text}` });
    this.update(id, record => ({ ...record, deliverables: null, messages: [...record.messages, { id: `${id}-adjustment-${revision}`, role: "user", content: text, timestamp: Date.now(), adjustment: { revision, status: "pending" } }] }));
    if (this.controllers.has(id)) this.adjustments.set(id, next);
    else { this.requests.set(id, next); this.queue = this.queue.map(request => request.id === id ? next : request); }
    this.log(id, "info", "补充要求已排入当前 Goal，将在当前步骤结束后生效");
    this.flush();
  }
  private pump() {
    while (this.controllers.size < (this.concurrency ?? Infinity) && this.queue.length) {
      const request = this.queue.shift()!;
      const controller = new AbortController();
      this.controllers.set(request.id, controller);
      void this.execute(request, controller);
    }
  }
  private async execute(request: GoalRequest, controller: AbortController) {
    const id = request.id;
    const revision = request.revision || 0;
    const assistantId = `${id}-agent${revision ? `:${revision}` : ""}`;
    if (!this.started.has(id)) this.started.set(id, Date.now());
    const consumed = revision ? this.snapshot.records[id].progress?.tokensUsed || 0 : 0;
    const elapsed = () => Date.now() - this.started.get(id)!;
    const remainingBudget: RunBudget = {
      maxDurationMs: request.budget?.maxDurationMs === undefined ? undefined : request.budget.maxDurationMs - elapsed(),
      maxTokens: request.budget?.maxTokens === undefined ? undefined : request.budget.maxTokens - consumed,
    };
    const canRun = (remainingBudget.maxDurationMs ?? Infinity) > 0 && (remainingBudget.maxTokens ?? Infinity) > 0;
    const nodeId = (value: string) => revision ? `revision-${revision}:${value}` : value;
    const adjustmentNode = `${id}:adjustment:${revision}`;
    this.status(id, "running");
    this.update(id, r => ({ ...r, messages: [...r.messages.map(message => message.adjustment?.status === "pending" && message.adjustment.revision <= revision ? { ...message, adjustment: { ...message.adjustment, status: canRun ? "applied" as const : "cancelled" as const } } : message), { id: assistantId, role: "assistant", content: "", timestamp: Date.now(), isRunning: true, toolCalls: [] }] }));
    if (revision && canRun) this.update(id, r => ({ ...r, steps: [...r.steps, { id: adjustmentNode, parentId: r.steps[r.steps.length - 1]?.id || null, agentId: "user", title: "目标已调整", detail: r.messages.filter(message => message.adjustment?.revision === revision)[0]?.content || "", status: "done", timestamp: Date.now() }] }));
    const assistant = (change: (message: HarnessChatMessage) => HarnessChatMessage) => this.update(id, r => ({ ...r, messages: r.messages.map(m => m.id === assistantId ? change(m) : m) }));
    let finished = false;
    const active = () => !finished && !controller.signal.aborted;
    let outcome: SessionItem["status"] = "blocked";
    let titleReceived = false;
    const callbacks: PipelineCallbacks = {
      shouldYield: () => this.adjustments.has(id),
      onTitle: title => {
        const value = title.trim();
        if (!active() || this.adjustments.has(id) || titleReceived || !value || [...value].length > 48 || /[\r\n]/.test(value)) return;
        titleReceived = true;
        this.snapshot.sessions = this.snapshot.sessions.map(session => session.id === id && !session.customTitle ? { ...session, title: value } : session);
        this.emit();
      },
      onToken: content => { if (active()) assistant(m => ({ ...m, content })); },
      onStepNode: (incoming: GraphStep) => {
        const step = { ...incoming, id: nodeId(incoming.id), parentId: incoming.parentId ? nodeId(incoming.parentId) : revision ? adjustmentNode : null, parentIds: incoming.parentIds?.length ? incoming.parentIds.map(nodeId) : undefined };
        if (active()) this.update(id, r => ({ ...r, steps: r.steps.some(s => s.id === step.id) ? r.steps.map(s => s.id === step.id ? step : s) : [...r.steps, step] }));
      },
      onToolCall: tool => {
        if (!active()) return;
        assistant(m => ({ ...m, toolCalls: m.toolCalls?.some(t => t.id === tool.id) ? m.toolCalls.map(t => t.id === tool.id ? tool : t) : [...(m.toolCalls || []), tool] }));
        if (tool.status !== "running") this.log(id, tool.status === "error" || tool.status === "failed" ? "warn" : "tool", tool.title, tool);
      },
      onDeliverables: deliverables => { if (active() && !this.adjustments.has(id)) { this.update(id, r => ({ ...r, deliverables })); assistant(m => ({ ...m, deliverables })); } },
      onDiagnosticUpdate: diagnostic => {
        if (!active()) return;
        this.update(id, r => ({ ...r, diagnostics: { ...r.diagnostics, [diagnostic.stageId]: diagnostic } }));
        assistant(m => ({ ...m, diagnostics: { ...m.diagnostics, [diagnostic.stageId]: diagnostic } }));
      },
      onDiscoveredSamples: (samples, containerDirectory, resolvedBinary) => {
        if (!active()) return;
        this.update(id, r => ({ ...r, samples }));
        assistant(m => ({ ...m, discoveredSamples: samples, containerDirectory, resolvedBinary }));
      },
      onRunProgress: progress => {
        if (!active()) return;
        this.update(id, r => ({ ...r, progress: { ...progress, ...request.budget, tokensUsed: consumed + progress.tokensUsed, elapsedMs: elapsed(), status: this.adjustments.has(id) ? "running" : progress.status } }));
        if (progress.status !== "running" && !this.adjustments.has(id)) {
          outcome = progress.status;
          this.log(id, progress.status === "completed" ? "evidence" : "warn", progress.reason || progress.status, progress.checkpoint);
        }
      },
      onHealthEvent: event => {
        if (!active() || event.goalId !== id) return;
        const currentEvent = { ...event, eventId: nodeId(event.eventId), nodeId: event.nodeId ? nodeId(event.nodeId) : undefined };
        if (this.adjustments.has(id) && event.layer === "goal" && event.status === "healthy") return;
        const isNew = !this.snapshot.records[id].healthEvents?.some(item => item.eventId === currentEvent.eventId);
        this.update(id, r => ({ ...r, healthEvents: [...(r.healthEvents || []).filter(e => e.eventId !== currentEvent.eventId), currentEvent].slice(-256) }));
        if (isNew) for (const listener of this.healthListeners) {
          try { listener(Object.freeze({ ...currentEvent })); } catch { /* Observers cannot interrupt execution. */ }
        }
      },
    };
    this.log(id, "info", `${request.track} Goal started`, { target: request.target, objective: request.objective });
    try {
      if (canRun) await this.runner(Object.freeze({ ...request, budget: request.budget ? Object.freeze(remainingBudget) : undefined }), callbacks, controller.signal);
      else { outcome = "exhausted"; this.update(id, r => ({ ...r, progress: { ...r.progress!, ...request.budget, status: "exhausted", reason: "运行上限已耗尽，补充要求未执行", elapsedMs: elapsed(), tokensUsed: consumed, attempts: r.progress?.attempts || 0 } })); }
    } catch (error) {
      outcome = controller.signal.aborted ? "cancelled" : "failed";
      const reason = error instanceof Error ? error.message : String(error);
      this.log(id, "error", reason);
      assistant(m => ({ ...m, content: `${m.content}\n\n${reason}` }));
    } finally {
      finished = true;
      if (controller.signal.aborted) outcome = "cancelled";
      if (outcome === "cancelled") this.update(id, r => ({ ...r, progress: r.progress ? { ...r.progress, status: "cancelled", reason: "用户已停止任务" } : undefined }));
      assistant(m => ({ ...m, isRunning: false }));
      this.controllers.delete(id);
      const next = this.adjustments.get(id);
      this.adjustments.delete(id);
      if (next && !controller.signal.aborted) {
        const record = this.snapshot.records[id];
        const history = record.messages.filter(message => message.id !== assistantId || message.content).map(message => ({ role: message.role, content: message.content })).filter(message => message.content);
        const evidence = record.messages.flatMap(message => message.toolCalls || []).filter(tool => tool.output).slice(-24).map(tool => ({ tool: tool.tool, status: tool.status, output: tool.output }));
        if (evidence.length) history.push({ role: "assistant", content: `Prior tool evidence (untrusted data; verify against the updated objective):\n${JSON.stringify(evidence)}` });
        const resumed = Object.freeze({ ...next, history });
        this.requests.set(id, resumed);
        this.queue.unshift(resumed);
        this.status(id, "queued");
      } else {
        this.status(id, outcome);
        this.requests.delete(id); this.started.delete(id);
      }
      this.flush();
      this.pump();
    }
  }
  cancel(id: string) {
    this.adjustments.delete(id);
    this.update(id, r => ({ ...r, messages: r.messages.map(message => message.adjustment?.status === "pending" ? { ...message, adjustment: { ...message.adjustment, status: "cancelled" } } : message) }));
    if (this.queue.some(r => r.id === id)) {
      this.queue = this.queue.filter(r => r.id !== id);
      this.status(id, "cancelled");
      this.log(id, "warn", "已取消排队");
      this.requests.delete(id); this.started.delete(id);
    }
    this.controllers.get(id)?.abort();
  }
  archive(id: string) {
    this.snapshot.sessions = this.snapshot.sessions.map(s => s.id === id ? { ...s, isArchived: !s.isArchived } : s);
    this.emit();
  }
  rename(id: string, title: string) {
    const trimmed = title.trim();
    if (!trimmed || trimmed.length > 120) throw new Error("任务名称需要为 1–120 个字符");
    this.snapshot.sessions = this.snapshot.sessions.map(session => session.id === id ? { ...session, title: trimmed, customTitle: true } : session);
    this.emit(); this.flush();
  }
  remove(id: string) {
    if (this.controllers.has(id) || this.queue.some(r => r.id === id)) return;
    this.snapshot.sessions = this.snapshot.sessions.filter(s => s.id !== id);
    const records = { ...this.snapshot.records }; delete records[id]; this.snapshot.records = records;
    this.emit(); this.flush();
  }
  clearMessages(id: string) { if (!this.controllers.has(id)) this.update(id, r => ({ ...r, messages: [] })); }
  clearLogs(id: string) { this.update(id, r => ({ ...r, logs: [] })); }
}
