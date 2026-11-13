import { useState, type ReactNode } from "react";

/** Mount a view on first use, then preserve its input, scroll and disclosure state. */
export function RetainedView({ active, children }: { active: boolean; children: ReactNode }) {
  const [visited, setVisited] = useState(active);
  if (active && !visited) setVisited(true);
  if (!active && !visited) return null;
  return <div className="retained-view" hidden={!active}>{children}</div>;
}
