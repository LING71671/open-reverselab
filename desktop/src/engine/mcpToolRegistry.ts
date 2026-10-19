import { tool } from "ai";
import { z } from "zod";
import { nativeBridge } from "../services";

export const mcpTools = {
  triage_target: tool({
    description:
      "Run deep binary static triage on a target executable, library, or URL to extract architecture, entry point, entropy, sections, and suspicious imports.",
    parameters: z.object({
      target: z.string().describe("Target binary file path, APK, or URL"),
    }),
    execute: async ({ target }) => {
      return await nativeBridge.triage(target);
    },
  }),

  execute_python: tool({
    description:
      "Execute forensic or verification Python code in the host execution environment.",
    parameters: z.object({
      script: z.string().describe("Full Python script to execute"),
    }),
    execute: async ({ script }) => {
      return await nativeBridge.execPython(script);
    },
  }),

  read_kb_doc: tool({
    description:
      "Read reverse engineering attack network or technique guide from the local knowledge base.",
    parameters: z.object({
      path: z
        .string()
        .describe("Relative path in kb, e.g. kb/pe-reverse/techniques/attack-network.md"),
    }),
    execute: async ({ path }) => {
      const content = await nativeBridge.readKb(path);
      return content
        ? { path, content: content.slice(0, 3000) }
        : { path, error: "Document not found" };
    },
  }),
};
