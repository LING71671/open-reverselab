import { useEffect, useRef, useState } from "react";
import { reviewSavedEvidence, savedObservations, type EvidenceReview } from "../../services/goals/evidenceReview";
import type { GoalRecord } from "../../services/goals/goalManager";

export function EvidenceReviewPanel({ record, save }: { record: GoalRecord; save: (result: EvidenceReview) => void }) {
  const pending = useRef<AbortController | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => () => { pending.current?.abort(); pending.current = null; }, []);

  const review = record.evidenceReview;
  if (review) return <section className="activity-message">
    <header><strong>证据复核</strong><span>{review.provider} · {review.model}</span></header>
    <p style={{ whiteSpace: "pre-wrap" }}>{review.text}</p>
  </section>;
  if (!savedObservations(record).length) return null;
  const start = async () => {
    if (pending.current) return;
    const controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    setError("");
    try {
      const result = await reviewSavedEvidence(record, controller.signal);
      if (!controller.signal.aborted) save(result);
    } catch (cause) {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      if (pending.current === controller) { pending.current = null; setBusy(false); }
    }
  };
  return <section className="activity-message">
    <div><button className="secondary-button" disabled={busy} onClick={start}>{busy ? "正在复核…" : "复核已有证据"}</button>
    {busy && <button className="text-button" onClick={() => pending.current?.abort()}>取消复核</button>}</div>
    {error && <p role="alert">{error}</p>}
  </section>;
}
