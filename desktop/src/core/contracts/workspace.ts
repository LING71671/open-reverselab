export interface Workspace { id: string; version: number; name: string; root: string; createdAt: number }
export interface WorkspaceSample { id: string; name: string; kind: "file" | "directory"; target: string; sha256: string; sizeBytes: number; importedAt: number }
