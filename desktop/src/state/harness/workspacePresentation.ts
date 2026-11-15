import type { ComposerDraft } from "../../core/contracts/composer";
import type { SecurityTrack } from "../../core/contracts/track";

type PresentationStorage = Pick<Storage, "getItem" | "setItem">;
interface WorkspaceSelection { track: SecurityTrack; byTrack: Partial<Record<SecurityTrack, string>> }
const tracks: SecurityTrack[] = ["red", "blue", "both"];
const memory = new Map<string, string>();
const isRecord = (value: unknown): value is Record<string, unknown> => !!value && typeof value === "object" && !Array.isArray(value);
const keyFor = (root: string, part: string) => `reverselab_presentation_v1:${JSON.stringify([root, part])}`;
const browserStorage = () => { try { return window.localStorage; } catch { return undefined; } };

function read(root: string, part: string, storage: PresentationStorage | undefined): unknown {
  const key = keyFor(root, part);
  try { return JSON.parse(memory.get(key) ?? storage?.getItem(key) ?? "null"); }
  catch { try { return JSON.parse(memory.get(key) ?? "null"); } catch { return null; } }
}

function write(root: string, part: string, value: unknown, storage: PresentationStorage | undefined) {
  const key = keyFor(root, part);
  const serialized = JSON.stringify(value);
  memory.set(key, serialized);
  try { storage?.setItem(key, serialized); } catch { /* Workspace switching still retains drafts in this session. */ }
}

export function readWorkspaceSelection(root: string, sessions: readonly { id: string; track: SecurityTrack }[], fallback: SecurityTrack = "blue", storage: PresentationStorage | undefined = browserStorage()): WorkspaceSelection {
  const saved = read(root, "selection", storage);
  if (!isRecord(saved)) return { track: fallback, byTrack: {} };
  const track = tracks.includes(saved.track as SecurityTrack) ? saved.track as SecurityTrack : fallback;
  const selected = isRecord(saved.byTrack) ? saved.byTrack : {};
  const byTrack: WorkspaceSelection["byTrack"] = {};
  for (const candidate of tracks) {
    const id = selected[candidate];
    if (typeof id === "string" && sessions.some(session => session.id === id && session.track === candidate)) byTrack[candidate] = id;
  }
  return { track, byTrack };
}

export function saveWorkspaceSelection(root: string, selection: WorkspaceSelection, storage: PresentationStorage | undefined = browserStorage()) {
  write(root, "selection", selection, storage);
}

export function readWorkspaceDrafts(root: string, storage: PresentationStorage | undefined = browserStorage()): Record<string, ComposerDraft> {
  const saved = read(root, "drafts", storage);
  if (!isRecord(saved)) return {};
  return Object.fromEntries(Object.entries(saved).filter(([, value]) => isRecord(value) &&
    ["target", "prompt", "instruction", "minutes", "tokens"].every(field => typeof value[field] === "string") && typeof value.limitsOpen === "boolean")
    .map(([id, value]) => {
      const draft = value as unknown as ComposerDraft;
      return [id, { target: draft.target, prompt: draft.prompt, instruction: draft.instruction, minutes: draft.minutes, tokens: draft.tokens, limitsOpen: draft.limitsOpen }];
    }));
}

export function saveWorkspaceDrafts(root: string, drafts: Record<string, ComposerDraft>, storage: PresentationStorage | undefined = browserStorage()) {
  write(root, "drafts", drafts, storage);
}
