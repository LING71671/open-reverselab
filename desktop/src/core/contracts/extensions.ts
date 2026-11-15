export interface ExtensionInput {
  name: string;
  type?: "string" | "url" | "path" | "secret";
  title?: string;
  description?: string;
  required?: boolean;
  default?: string;
}

export interface McpDescriptor {
  transport: "stdio" | "streamable-http";
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
  headers?: Record<string, string>;
  inputs?: ExtensionInput[];
}

export interface ExtensionEntry {
  id: string;
  kind: "knowledge" | "mcp";
  title: string;
  version: string;
  description?: string;
  descriptor?: McpDescriptor;
  source?: { identity?: string; url?: string; commit?: string; path?: string; label?: string };
  requires?: Array<{ id: string; version: string; source: string; optional: boolean }>;
}

export interface InstalledExtension extends ExtensionEntry {
  installationId: string;
  enabled: boolean;
  digest: string;
  source: { identity?: string; url?: string; commit?: string; path?: string; label?: string };
}

export interface ExtensionInspection {
  inspectionId: string;
  entries: ExtensionEntry[];
  source?: unknown;
  warnings?: string[];
}

export interface ExtensionSource {
  sourceId: string;
  title?: string;
  source?: string;
  url?: string;
  lastRefresh?: string;
  error?: string;
}

export interface McpTool {
  id: string;
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export interface McpConnection {
  id: string;
  name: string;
  installationId?: string;
  transport: "stdio" | "streamable-http";
  enabled: boolean;
  status: "ready" | "unconfigured" | "disconnected" | "error" | "unavailable";
  connected: false;
  sessionMode: "per-request";
  tools: McpTool[];
  resources: Array<{ uri: string; name?: string; description?: string }>;
  inputs?: ExtensionInput[];
  configuredInputs?: string[];
  error?: string | { code?: string; message?: string };
}
