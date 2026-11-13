import { defineConfig, Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
// @ts-expect-error type error without @types/node package
import process from "node:process";
import { execFile } from "node:child_process";
import { writeFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve } from "node:path";

const host = process.env.TAURI_DEV_HOST;
const repoRoot = resolve(import.meta.dirname, "..");

function reverseLabNativePlugin(): Plugin {
  return {
    name: "reverselab-native-backend",
    configureServer(server) {
      server.middlewares.use("/api/workspace", (req, res, next) => {
        if (req.method !== "POST") return next();
        req.setEncoding("utf8");
        let body = "";
        req.on("data", chunk => { body += chunk; if (body.length > 32 * 1024 * 1024) req.destroy(); });
        req.on("end", () => {
          try { JSON.parse(body); } catch { res.statusCode = 400; res.end(JSON.stringify({ error: "Invalid request" })); return; }
          const child = execFile("python", [resolve(repoRoot, "scripts/misc/desktop_workspace.py")], { cwd: repoRoot, timeout: 120000, maxBuffer: 32 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
            res.setHeader("Content-Type", "application/json; charset=utf-8");
            if (err) res.statusCode = 400;
            try { res.end(JSON.stringify(JSON.parse(stdout))); }
            catch { res.statusCode = 500; res.end(JSON.stringify({ error: stderr || err?.message || "Workspace unavailable" })); }
          });
          child.stdin?.end(body);
        });
      });
      const serveKnowledge = (args: string[], res: import("node:http").ServerResponse) => {
        execFile(
          "python",
          [resolve(repoRoot, "scripts/misc/desktop_kb.py"), ...args],
          { cwd: repoRoot, timeout: 15000, maxBuffer: 16 * 1024 * 1024, windowsHide: true },
          (err, stdout, stderr) => {
            res.setHeader("Content-Type", "application/json; charset=utf-8");
            try {
              const payload = JSON.parse(stdout);
              if (err) res.statusCode = payload.status || 400;
              res.end(JSON.stringify(payload));
            } catch {
              res.statusCode = 500;
              res.end(JSON.stringify({ error: stderr || err?.message || "Invalid knowledge base response" }));
            }
          },
        );
      };

      server.middlewares.use("/api/kb/techniques", (req, res, next) => {
        if (req.method !== "GET") return next();
        const url = new URL(req.url || "", "http://localhost");
        serveKnowledge(["list", "--track", url.searchParams.get("track") || "both"], res);
      });

      server.middlewares.use("/api/kb/doc", (req, res, next) => {
        if (req.method !== "GET") return next();
        const url = new URL(req.url || "", "http://localhost");
        serveKnowledge(["read", "--path", url.searchParams.get("path") || ""], res);
      });

      // 1. Live Triage endpoint: POST /api/system/triage
      server.middlewares.use("/api/system/triage", (req, res, next) => {
        if (req.method !== "POST") return next();
        req.setEncoding("utf8");
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", () => {
          try {
            const { target, timeoutMs } = JSON.parse(body || "{}");
            const script = resolve(repoRoot, "scripts/misc/triage_target.py");
            const child = execFile(
              "python",
              [script, target || "target.bin"],
              { cwd: repoRoot, timeout: Math.max(1, Math.min(15000, Number.isFinite(timeoutMs) ? Math.floor(timeoutMs) : 15000)), windowsHide: true },
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
            res.on("close", () => { if (!res.writableEnded) child.kill(); });
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
        req.setEncoding("utf8");
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", () => {
          try {
            const { script, timeoutMs } = JSON.parse(body || "{}");
            if (typeof script !== "string" || !script.trim()) throw new Error("A Python script is required");
            const start = Date.now();
            const limit = Math.max(1, Math.min(60000, Number.isFinite(timeoutMs) ? Math.floor(timeoutMs) : 15000));
            let timer: ReturnType<typeof setTimeout> | undefined;
            let stopped = false;
            const child = execFile(
              "python",
              ["-c", script],
              { cwd: repoRoot, maxBuffer: 4 * 1024 * 1024, windowsHide: true, env: { ...process.env, PYTHONIOENCODING: "utf-8" } },
              (err, stdout, stderr) => {
                if (timer) clearTimeout(timer);
                if (res.destroyed) return;
                res.setHeader("Content-Type", "application/json");
                res.end(
                  JSON.stringify({
                    success: !err && !stopped,
                    stdout: stdout || "",
                    stderr: stopped ? `${stderr || ""}\nExecution cancelled or time budget exhausted` : stderr || (err ? err.message : ""),
                    durationMs: Date.now() - start,
                    executionTimeMs: Date.now() - start,
                  })
                );
              }
            );
            const terminate = () => {
              if (child.exitCode !== null || child.killed) return;
              stopped = true;
              if (process.platform === "win32" && child.pid) {
                execFile("taskkill", ["/PID", String(child.pid), "/T", "/F"], { windowsHide: true }, () => child.kill());
              } else child.kill("SIGKILL");
            };
            timer = setTimeout(terminate, limit);
            res.on("close", () => { if (!res.writableEnded) terminate(); });
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
          serveKnowledge(["read", "--path", relPath], res);
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

      // 5. Real Report & Script saving: POST /api/system/save-report
      server.middlewares.use("/api/system/save-report", (req, res, next) => {
        if (req.method !== "POST") return next();
        req.setEncoding("utf8");
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", () => {
          try {
            const { target, summary, script, key, flag, executionOutput, goalId, track, attempt } = JSON.parse(body || "{}");
            const safeComponent = (value: string) => value.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 100) || "session";
            const scope = `${safeComponent(String(goalId || "session"))}/${safeComponent(String(track || "blue"))}-${Math.max(1, Math.floor(Number(attempt) || 1))}`;
            const cleanName = safeComponent((target || "target")
              .split(/[\\/]/)
              .pop()
              .replace(/\.[^/.]+$/, ""));
            const reportsDir = resolve(repoRoot, "reports", scope);
            const exportsDir = resolve(repoRoot, "exports", scope);
            mkdirSync(reportsDir, { recursive: true });
            mkdirSync(exportsDir, { recursive: true });

            const reportRel = `reports/${scope}/${cleanName}_analysis.md`;
            const scriptRel = `exports/${scope}/${cleanName}_forensics.py`;
            const reportPath = resolve(repoRoot, reportRel);
            const scriptPath = resolve(repoRoot, scriptRel);

            let reportMd = `# Analysis Report: ${target}\n\n## 1. Summary\n${summary}\n\n## 2. Key Artifacts\n- Target: ${target}\n- Fingerprint: ${key || "None"}\n- Verdict: ${flag || "Unverified"}\n\n## 3. Script\n\`\`\`python\n${script}\n\`\`\`\n`;
            if (executionOutput) {
              reportMd += `\n## 4. Execution Output\n\`\`\`json\n${JSON.stringify(executionOutput, null, 2)}\n\`\`\`\n`;
            }
            writeFileSync(reportPath, reportMd, "utf-8");
            writeFileSync(scriptPath, script || "# Empty script\n", "utf-8");

            res.setHeader("Content-Type", "application/json");
            res.end(
              JSON.stringify({
                status: "saved",
                report_path: reportRel,
                script_path: scriptRel,
              })
            );
          } catch (e: any) {
            res.statusCode = 500;
            res.end(JSON.stringify({ error: e.message }));
          }
        });
      });

      // 6. Autonomous Headless Harness Execution endpoint: POST /api/harness/run
      server.middlewares.use("/api/harness/run", (req, res, next) => {
        if (req.method !== "POST") return next();
        req.setEncoding("utf8");
        let body = "";
        req.on("data", (chunk) => (body += chunk));
        req.on("end", () => {
          try {
            const { target, prompt, model } = JSON.parse(body || "{}");
            const script = resolve(repoRoot, "scripts/misc/run_harness.py");
            const args = [
              script,
              "--target",
              target || "target.bin",
              "--prompt",
              prompt || "深度静态排查与反调试/注册表行为分析",
              "--output-json",
            ];
            if (model) {
              args.push("--model", model);
            }
            execFile("python", args, { cwd: repoRoot, timeout: 60000 }, (err, stdout, stderr) => {
              res.setHeader("Content-Type", "application/json");
              if (err && !stdout) {
                res.statusCode = 500;
                res.end(JSON.stringify({ error: stderr || err.message }));
              } else {
                try {
                  const jsonStr = stdout.slice(stdout.indexOf("{"));
                  res.end(jsonStr);
                } catch {
                  res.end(stdout);
                }
              }
            });
          } catch (e: any) {
            res.statusCode = 400;
            res.end(JSON.stringify({ error: e.message }));
          }
        });
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
