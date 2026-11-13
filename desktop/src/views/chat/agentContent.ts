export interface AgentContent {
  prose: string;
  details: Array<{ label: string; content: string }>;
}

function objectEnd(content: string, start: number): number {
  let depth = 0, quoted = false, escaped = false;
  for (let index = start; index < content.length; index++) {
    const char = content[index];
    if (quoted) {
      if (escaped) escaped = false;
      else if (char === "\\") escaped = true;
      else if (char === '"') quoted = false;
    } else if (char === '"') quoted = true;
    else if (char === "{") depth++;
    else if (char === "}" && --depth === 0) return index + 1;
  }
  return content.length;
}

/** Presentation only: the engine and saved transcript retain the exact model output. */
export function presentAgentContent(content: string): AgentContent {
  const details: AgentContent["details"] = [];
  const prose: string[] = [];
  let cursor = 0;
  // Also handles concatenated objects produced by providers which omit fences.
  const opening = /(^|\n)[ \t]*(```([^\n]*)(?:\n|$)|\{)/g;
  while (cursor < content.length) {
    opening.lastIndex = cursor;
    const match = opening.exec(content);
    if (!match) { prose.push(content.slice(cursor)); break; }
    const start = match.index + match[1].length;
    prose.push(content.slice(cursor, start));
    let raw: string, end: number;
    const language = (match[3] || "").trim().toLowerCase();
    if (match[2].startsWith("```")) {
      const closing = /(^|\n)[ \t]*```[ \t]*(?=\n|$)/g;
      closing.lastIndex = opening.lastIndex;
      const close = closing.exec(content);
      raw = content.slice(opening.lastIndex, close ? close.index : content.length);
      end = close ? closing.lastIndex : content.length;
    } else {
      const brace = content.indexOf("{", start);
      end = objectEnd(content, brace);
      raw = content.slice(brace, end);
    }
    let value: any;
    try { value = JSON.parse(raw); } catch { /* Hide incomplete protocol while streaming. */ }
    const label = language === "goal-plan" || Array.isArray(value?.checks) ? "验收计划"
      : language === "action-plan" || Array.isArray(value?.actions) ? "动作与脚本" : language ? `${language} 代码` : "结构化数据";
    details.push({ label, content: value ? JSON.stringify(value, null, 2) : raw });
    // Older records may contain only protocol. Their explicit hypothesis is a
    // plan, not a finding, and can be shown without exposing scripts or JSON.
    if (typeof value?.hypothesis === "string" && value.hypothesis.trim()) prose.push(`\n核查计划：${value.hypothesis.trim()}\n`);
    cursor = end;
    // Adjacent raw objects do not have a line break to anchor the next match.
    while (content[cursor] === "{") {
      const next = objectEnd(content, cursor);
      const adjacent = presentAgentContent(content.slice(cursor, next));
      details.push(...adjacent.details);
      prose.push(adjacent.prose);
      cursor = next;
    }
  }
  return { prose: prose.join("").replace(/\n{3,}/g, "\n\n").trim(), details };
}
