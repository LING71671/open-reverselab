import type { DiagnosticItem } from "../../core";
import { nativeBridge } from "../native/nativeBridge";

const probe = `import sys, json, shutil, importlib.util
items = [{'id':'python', 'category':'toolchain', 'name':'Python', 'status':'pass', 'detail':sys.version.split()[0]}]
for name in ['pefile', 'capstone', 'frida', 'yara']:
    available = importlib.util.find_spec(name) is not None
    items.append({'id':name,'category':'toolchain','name':name,'status':'pass' if available else 'warn','detail':'模块可用' if available else '未安装'})
for name in ['git','java','adb','ghidra','diec']:
    location = shutil.which(name)
    items.append({'id':name,'category':'toolchain','name':name,'status':'pass' if location else 'warn','detail':location or '未在 PATH 中发现'})
print(json.dumps(items))`;
class DiagnosticService {
  private items: DiagnosticItem[] = [];
  public async runFullDiagnostics(_target?: string): Promise<DiagnosticItem[]> {
    const output = await nativeBridge.execPython(probe, { timeoutMs: 8000 });
    if (!output.success) throw new Error(output.stderr || "工具检测失败");
    const result = JSON.parse(output.stdout);
    if (!Array.isArray(result)) throw new Error("工具检测结果格式错误");
    this.items = result;
    return this.getCached();
  }
  public getCached() { return [...this.items]; }
}
export const diagnosticService = new DiagnosticService();
