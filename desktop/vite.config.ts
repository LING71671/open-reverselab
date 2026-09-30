import { defineConfig, Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
// @ts-expect-error type error without @types/node package
import process from "node:process";
import { execFile } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";

const host = process.env.TAURI_DEV_HOST;
const repoRoot = resolve(import.meta.dirname, "..");

function reverseLabNativePlugin(): Plugin {
  return {
    name: "reverselab-native-backend",
    configureServer(server) {
      // 1. Live Triage endpoint: POST /api/system/triage
      server.middlewares.use("/api/system/triage", (req, res, next) => {
        if (req.method !== "POST") return next();
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", () => {
          try {
            const { target } = JSON.parse(body || "{}");
            const script = resolve(repoRoot, "scripts/misc/triage_target.py");
            execFile(
              "python",
              [script, target || "target.bin"],
              { cwd: repoRoot, timeout: 15000 },
              (err, stdout, stderr) => {
                res.setHeader("Content-Type", "application/json");
                if (err) {
                  res.statusCode = 500;
                  res.end(JSON.stringify({ error: stderr || err.message }));
                } else {
                  res.end(stdout);
                }
              }
            );
          } catch (e: any) {
            res.statusCode = 400;
            res.end(JSON.stringify({ error: e.message }));
          }
        });
      });

      // 2. Real Diagnostics endpoint: GET /api/system/diagnostics
      server.middlewares.use("/api/system/diagnostics", (req, res, next) => {
        if (req.method !== "GET") return next();
        const pyCode = `
import sys, json, shutil
results = []
results.append({'id': 'diag-py', 'category': 'toolchain', 'name': 'Python 3 逆向运行时', 'status': 'pass', 'detail': f'Python {sys.version.split()[0]} ({sys.executable})'})
for mod, name in [('pefile', 'Pefile PE解析引擎'), ('capstone', 'Capstone 反汇编引擎'), ('frida', 'Frida 动态插桩驱动'), ('yara', 'Yara 威胁特征匹配')]:
    try:
        m = __import__(mod)
        ver = getattr(m, '__version__', 'ready')
        results.append({'id': f'diag-{mod}', 'category': 'toolchain', 'name': name, 'status': 'pass', 'detail': f'{mod} {ver} 已就绪'})
    except Exception:
        results.append({'id': f'diag-{mod}', 'category': 'toolchain', 'name': name, 'status': 'warn', 'detail': f'{mod} 缺失'})
for tool, cat in [('git', 'system'), ('node', 'system'), ('java', 'system'), ('adb', 'toolchain')]:
    loc = shutil.which(tool)
    if loc:
        results.append({'id': f'diag-{tool}', 'category': cat, 'name': f'{tool.upper()} 命令行工具', 'status': 'pass', 'detail': loc})
    else:
        results.append({'id': f'diag-{tool}', 'category': cat, 'name': f'{tool.upper()} 命令行工具', 'status': 'warn', 'detail': '未安装或不在 PATH'})
print(json.dumps(results))
`;
        execFile("python", ["-c", pyCode], { cwd: repoRoot, timeout: 8000 }, (err, stdout, stderr) => {
          res.setHeader("Content-Type", "application/json");
          if (err) {
            res.statusCode = 500;
            res.end(JSON.stringify({ error: stderr || err.message }));
          } else {
            res.end(stdout);
          }
        });
      });

      // 3. Real Script Execution endpoint: POST /api/system/exec-python
      server.middlewares.use("/api/system/exec-python", (req, res, next) => {
        if (req.method !== "POST") return next();
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", () => {
          try {
            const { script } = JSON.parse(body || "{}");
            const start = Date.now();
            execFile(
              "python",
              ["-c", script || "print('No script specified')"],
              { cwd: repoRoot, timeout: 15000 },
              (err, stdout, stderr) => {
                res.setHeader("Content-Type", "application/json");
                res.end(
                  JSON.stringify({
                    success: !err,
                    stdout: stdout || "",
                    stderr: stderr || (err ? err.message : ""),
                    durationMs: Date.now() - start,
                    executionTimeMs: Date.now() - start,
                  })
                );
              }
            );
          } catch (e: any) {
            res.statusCode = 400;
            res.end(JSON.stringify({ error: e.message }));
          }
        });
      });

      // 4. Real Knowledge Base document reading: GET /api/system/kb
      server.middlewares.use("/api/system/kb", (req, res, next) => {
        if (req.method !== "GET") return next();
        const urlObj = new URL(req.url || "", "http://localhost:1420");
        const relPath = urlObj.searchParams.get("path");
        res.setHeader("Content-Type", "application/json");
        if (relPath) {
          const fullPath = resolve(repoRoot, relPath);
          if (existsSync(fullPath)) {
            const content = readFileSync(fullPath, "utf-8");
            res.end(JSON.stringify({ content }));
          } else {
            res.statusCode = 404;
            res.end(JSON.stringify({ error: "Document not found" }));
          }
        } else {
          const boards = ["pe-reverse", "apk-reverse", "ctf-website", "general"];
          const list = boards.map((b) => ({
            board: b,
            attackNetwork: `kb/${b}/techniques/attack-network.md`,
            exists: existsSync(resolve(repoRoot, `kb/${b}/techniques/attack-network.md`)),
          }));
          res.end(JSON.stringify({ list }));
        }
      });
    },
  };
}

// https://vite.dev/config/
export default defineConfig(() => ({
  plugins: [react(), tailwindcss(), reverseLabNativePlugin()],

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    proxy: {
      "/api/llm": {
        target: "https://tokenrhythm.studio",
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/api\/llm/, ""),
        configure: (proxy) => {
          proxy.on("proxyReq", (proxyReq) => {
            // Strip origin and referer headers to prevent TokenRhythm CSRF_INVALID rejection
            proxyReq.removeHeader("origin");
            proxyReq.removeHeader("referer");
          });
        },
      },
    },
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
}));
