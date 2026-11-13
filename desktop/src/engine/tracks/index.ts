import { redPolicy } from "./red";
import { bluePolicy } from "./blue";
import type { TrackPolicy } from "./contract";

export const trackPolicies: Record<"red" | "blue", TrackPolicy> = {
  red: redPolicy,
  blue: bluePolicy,
};
