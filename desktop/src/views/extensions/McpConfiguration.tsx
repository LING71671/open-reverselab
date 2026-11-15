import { useState } from "react";
import type { InstalledExtension, McpConnection } from "../../core/contracts/extensions";
import { Select } from "../controls/Select";

export function McpConfiguration({ entry, connection, busy, onSave, onClose }: {
  entry?: InstalledExtension;
  connection?: McpConnection;
  busy: boolean;
  onSave: (request: Record<string, unknown>) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState(connection?.name || entry?.title || "");
  const [transport, setTransport] = useState<"stdio" | "streamable-http">(entry?.descriptor?.transport || connection?.transport || "stdio");
  const [command, setCommand] = useState("");
  const [args, setArgs] = useState("");
  const [url, setUrl] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [environment, setEnvironment] = useState("");
  const [error, setError] = useState("");
  const inputs = entry?.descriptor?.inputs || connection?.inputs || [];
  const save = () => {
    setError("");
    try {
      const inputsToSave = Object.fromEntries(Object.entries(values).filter(([, value]) => value !== ""));
      for (const input of inputs) {
        if (input.required && !inputsToSave[input.name] && !connection?.configuredInputs?.includes(input.name) && !input.default) throw new Error(`请填写 ${input.title || input.name}`);
      }
      if (entry) {
        onSave({ operation: "configure", installationId: entry.installationId, inputs: inputsToSave, connection: { ...(connection ? { id: connection.id } : {}), name: name.trim() || entry.title } });
        return;
      }
      if (!name.trim()) throw new Error("请填写连接名称");
      let variables: Record<string, string> = {};
      if (environment.trim()) {
        variables = JSON.parse(environment);
        if (!variables || Array.isArray(variables) || typeof variables !== "object" || Object.values(variables).some(value => typeof value !== "string")) throw new Error("环境变量和请求头须为字符串值的 JSON 对象");
      }
      if (transport === "stdio" && !command.trim()) throw new Error("请填写启动命令");
      if (transport === "streamable-http") {
        const parsed = new URL(url);
        if (!["https:", "http:"].includes(parsed.protocol) || parsed.username || parsed.password) throw new Error("请填写 HTTP 或 HTTPS 地址，凭据单独放入请求头");
      }
      onSave({ operation: "configure", connection: {
        ...(connection ? { id: connection.id } : {}), name: name.trim(), transport,
        ...(transport === "stdio" ? { command: command.trim(), args: args.split("\n").filter(Boolean), env: variables } : { url: url.trim(), headers: variables }),
      } });
    } catch (err) { setError(err instanceof Error ? err.message : "配置格式无效"); }
  };
  return <form className="extension-config" aria-label={entry ? `配置 ${entry.title}` : "新增 MCP 连接"} onSubmit={event => { event.preventDefault(); save(); }}>
    <h3>{entry ? `配置 ${entry.title}` : "新增 MCP 连接"}</h3>
    <label>连接名称<input value={name} onChange={event => setName(event.target.value)} disabled={busy} autoComplete="off" /></label>
    {entry ? <>
      <p className="extension-meta">{entry.descriptor?.transport === "stdio" ? "本地进程" : "HTTP"}{entry.descriptor?.command ? ` · ${entry.descriptor.command}` : ""}</p>
      {inputs.map(input => <label key={input.name}>{input.title || input.name}{input.required ? " *" : ""}<input type={input.type === "secret" ? "password" : input.type === "url" ? "url" : "text"} value={values[input.name] ?? ""} placeholder={connection?.configuredInputs?.includes(input.name) ? "已配置，留空保留" : input.default || ""} autoComplete="off" spellCheck={false} disabled={busy} onChange={event => setValues(previous => ({ ...previous, [input.name]: event.target.value }))} />{input.description && <small>{input.description}</small>}</label>)}
    </> : <>
      <label>连接方式<Select label="连接方式" value={transport} onChange={value => setTransport(value as typeof transport)} disabled={busy} options={[{ value: "stdio", label: "本地进程（stdio）" }, { value: "streamable-http", label: "HTTP（Streamable HTTP）" }]} /></label>
      {transport === "stdio" ? <><label>启动命令<input value={command} onChange={event => setCommand(event.target.value)} spellCheck={false} disabled={busy} /></label><label>参数（每行一个）<textarea rows={3} value={args} onChange={event => setArgs(event.target.value)} spellCheck={false} disabled={busy} /></label></> : <label>MCP 地址<input type="url" value={url} onChange={event => setUrl(event.target.value)} disabled={busy} spellCheck={false} /></label>}
      <label>{transport === "stdio" ? "环境变量（JSON，可选）" : "请求头（JSON，可选）"}<textarea rows={3} value={environment} onChange={event => setEnvironment(event.target.value)} autoComplete="off" spellCheck={false} disabled={busy} /></label>
    </>}
    <small>配置保存在本机。验证时启动服务并读取工具目录；后续调用按次建立连接。</small>
    {error && <p role="alert" className="field-error">{error}</p>}
    <div className="extension-form-actions"><button className="text-button" type="button" onClick={onClose} disabled={busy}>取消</button><button className="primary-button" type="submit" disabled={busy}>保存配置</button></div>
  </form>;
}
