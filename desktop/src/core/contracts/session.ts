export interface SessionItem {
  id: string;
  title: string;
  target: string;
  time: string;
  status: "idle" | "running" | "completed";
  isArchived?: boolean;
}
