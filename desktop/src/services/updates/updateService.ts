import { Channel, invoke, isTauri } from "@tauri-apps/api/core";
import { getWorkloadCount, persistWorkspacesForUpdate } from "../goals/workspaceRuntime";
import { UpdateController, type InstallationInfo, type Release, type UpdateProgress, type UpdateStorage } from "./updateController";
import application from "../../../package.json";

let storage: UpdateStorage | undefined;
try { storage = localStorage; } catch { /* Preferences can remain in memory. */ }
export const updateService = new UpdateController({
  info: () => isTauri() ? invoke<InstallationInfo>("update_installation_info") : Promise.resolve({ version: application.version, mode: "browser" }),
  check: () => invoke<Release | null>("update_check"),
  download: onProgress => {
    const progress = new Channel<UpdateProgress>();
    progress.onmessage = onProgress;
    return invoke("update_download", { onProgress: progress });
  },
  install: () => invoke("update_install"),
}, application.version, storage, getWorkloadCount, persistWorkspacesForUpdate);
