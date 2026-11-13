/** Read complete leading JSON objects, including adjacent objects without fences. */
export function leadingJsonObjects(content: string): unknown[] {
  const objects: unknown[] = [];
  let start = 0;
  while (start < content.length) {
    while (/\s/.test(content[start] || "") && start < content.length) start++;
    if (content[start] !== "{") break;
    let depth = 0, quoted = false, escaped = false, end = start;
    for (; end < content.length; end++) {
      const char = content[end];
      if (quoted) {
        if (escaped) escaped = false;
        else if (char === "\\") escaped = true;
        else if (char === '"') quoted = false;
      } else if (char === '"') quoted = true;
      else if (char === "{") depth++;
      else if (char === "}" && --depth === 0) break;
    }
    if (end === content.length) break;
    try { objects.push(JSON.parse(content.slice(start, end + 1))); } catch { break; }
    start = end + 1;
  }
  return objects;
}

export function structuredPlanCandidates(content: string): any[] {
  const raw = leadingJsonObjects(content);
  for (const block of content.matchAll(/```json\s*([\s\S]*?)\s*```/gi)) raw.push(...leadingJsonObjects(block[1]));
  return raw;
}
