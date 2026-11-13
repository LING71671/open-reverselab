import type { SecurityTrack } from "./track";

export interface SessionItem {
  id: string;
  title: string;
  target: string;
  time: string;
  status: "idle" | "queued" | "running" | "completed" | "failed" | "cancelled" | "blocked" | "exhausted";
  track: SecurityTrack;
  isArchived?: boolean;
}
