import assert from "node:assert/strict";
import test from "node:test";
import { UpdateController, UPDATE_INTERVAL, UPDATE_STORAGE_KEY, type UpdateAdapter } from "../src/services/updates/updateController.ts";

function setup(options: { workload?: () => number; persist?: () => Promise<void>; adapter?: Partial<UpdateAdapter>; saved?: string; version?: string } = {}) {
  const calls = { check: 0, download: 0, install: 0, persist: 0 };
  const values = new Map<string, string>();
  if (options.saved) values.set(UPDATE_STORAGE_KEY, options.saved);
  const adapter: UpdateAdapter = {
    info: async () => ({ version: "2.0.0", mode: "installed" }),
    check: async () => { calls.check++; return { status: "available", release: { version: "2.1.0", notes: "Release notes", url: "https://github.com/LING71671/open-reverselab/releases/tag/v2.1.0" } }; },
    download: async progress => { calls.download++; progress({ downloaded: 50, total: 100 }); },
    install: async () => { calls.install++; },
    ...options.adapter,
  };
  const controller = new UpdateController(adapter, options.version || "2.0.0", { getItem: key => values.get(key) || null, setItem: (key, value) => { values.set(key, value); } }, options.workload || (() => 0), options.persist || (async () => { calls.persist++; }));
  return { controller, calls, values };
}

test("background checks are throttled and never download or install", async () => {
  const { controller, calls } = setup();
  await controller.check(false, UPDATE_INTERVAL);
  await controller.check(false, UPDATE_INTERVAL + 1000);
  assert.equal(calls.check, 1);
  assert.equal(calls.download + calls.install, 0);
  controller.setAutomatic(false);
  await controller.check(false, 4 * UPDATE_INTERVAL);
  assert.equal(calls.check, 1);
  await controller.check(true, 4 * UPDATE_INTERVAL);
  assert.equal(calls.check, 2);
});

test("skipping a version survives navigation while manual checks restore its notice", async () => {
  const { controller, values } = setup();
  await controller.check(); controller.skip();
  assert.equal(JSON.parse(values.get(UPDATE_STORAGE_KEY)!).skippedVersion, "2.1.0");
  await controller.check(false, Date.now() + UPDATE_INTERVAL + 1);
  assert.equal(controller.getSnapshot().preferences.skippedVersion, "2.1.0");
  await controller.check(true);
  assert.equal(controller.getSnapshot().preferences.skippedVersion, "");
});

test("running or queued work prevents exit, then persisted idle work can install", async () => {
  let tasks = 1;
  const { controller, calls } = setup({ workload: () => tasks });
  await controller.check(); await controller.download(); await controller.install();
  assert.equal(controller.getSnapshot().error?.code, "UPDATE_TASKS_ACTIVE");
  assert.equal(calls.install, 0);
  tasks = 0;
  await controller.install();
  assert.equal(calls.persist, 1);
  assert.equal(calls.install, 1);
});

test("new work during persistence also prevents installation", async () => {
  let tasks = 0;
  const { controller, calls } = setup({ workload: () => tasks, persist: async () => { tasks = 1; } });
  await controller.check(); await controller.download(); await controller.install();
  assert.equal(calls.install, 0);
  assert.equal(controller.getSnapshot().phase, "ready");
  assert.equal(controller.getSnapshot().error?.code, "UPDATE_TASKS_ACTIVE");
});

test("failed persistence keeps the app open with a ready update", async () => {
  const { controller, calls } = setup({ persist: async () => { throw new Error("disk full"); } });
  await controller.check(); await controller.download(); await controller.install();
  assert.equal(calls.install, 0);
  assert.equal(controller.getSnapshot().phase, "ready");
  assert.equal(controller.getSnapshot().error?.code, "UPDATE_STORAGE");
});

test("a failed signature can never advance to installable state", async () => {
  const { controller, calls } = setup({ adapter: { download: async () => { throw { code: "UPDATE_SIGNATURE", message: "bad signature" }; } } });
  await controller.check(); await controller.download(); await controller.install();
  assert.equal(controller.getSnapshot().phase, "available");
  assert.equal(controller.getSnapshot().error?.code, "UPDATE_SIGNATURE");
  assert.equal(calls.install, 0);
});

test("portable packages check versions but cannot invoke installer operations", async () => {
  const { controller, calls } = setup({ adapter: { info: async () => ({ version: "2.0.0", mode: "portable" }) } });
  await controller.check(); await controller.download(); await controller.install();
  assert.equal(calls.check, 1);
  assert.equal(calls.download + calls.install, 0);
});

test("browser preview does not pretend it reached the update service", async () => {
  const { controller, calls } = setup({ adapter: { info: async () => ({ version: "2.0.0", mode: "browser" }) } });
  await controller.check();
  assert.equal(calls.check, 0);
  assert.equal(controller.getSnapshot().phase, "idle");
});

test("concurrent clicks share one operation and progress uses actual bytes", async () => {
  let finish!: () => void;
  const { controller, calls } = setup({ adapter: { download: async progress => { progress({ downloaded: 7 }); await new Promise<void>(resolve => { finish = resolve; }); } } });
  await Promise.all([controller.check(), controller.check()]);
  assert.equal(calls.check, 1);
  const downloading = controller.download();
  await controller.download(); await controller.check();
  assert.equal(calls.check, 1);
  assert.equal(controller.getSnapshot().progress.downloaded, 7);
  assert.equal(controller.getSnapshot().progress.total, undefined);
  finish(); await downloading;
  assert.equal(controller.getSnapshot().phase, "ready");
});

test("check failures remain errors and are throttled in background", async () => {
  let attempts = 0;
  const { controller } = setup({ adapter: { check: async () => { attempts++; throw new Error("offline"); } }, saved: "broken JSON" });
  await controller.check(false, UPDATE_INTERVAL);
  await controller.check(false, UPDATE_INTERVAL + 1000);
  assert.equal(attempts, 1);
  assert.equal(controller.getSnapshot().phase, "error");
  assert.equal(controller.getSnapshot().error?.code, "UPDATE_NETWORK");
});

test("beta builds default to beta, and explicit channel preferences survive restarts", () => {
  const beta = setup({ version: "2.0.0-beta.1", saved: JSON.stringify({ automatic: false, lastChecked: 123, skippedVersion: "2.0.0" }) });
  assert.equal(beta.controller.getSnapshot().preferences.channel, "beta");
  assert.equal(beta.controller.getSnapshot().preferences.lastChecked, 0);
  assert.equal(beta.controller.getSnapshot().preferences.automatic, false);
  beta.controller.setChannel("stable");
  const restored = setup({ version: "2.0.0-beta.1", saved: beta.values.get(UPDATE_STORAGE_KEY) });
  assert.equal(restored.controller.getSnapshot().preferences.channel, "stable");
  assert.equal(setup({ version: "2.0.0+build-beta" }).controller.getSnapshot().preferences.channel, "stable");
});

test("changing channels invalidates the downloaded package and resets its check and skip state", async () => {
  const channels: string[] = [];
  const { controller, calls } = setup({ adapter: { check: async channel => {
    channels.push(channel);
    return { status: "available", release: { version: "2.1.0", notes: "", url: "https://github.com/LING71671/open-reverselab/releases/tag/v2.1.0" } };
  } } });
  await controller.check(); controller.skip(); await controller.download();
  assert.equal(controller.getSnapshot().phase, "ready");
  controller.setChannel("beta");
  await controller.install();
  assert.equal(calls.install, 0);
  assert.equal(controller.getSnapshot().phase, "idle");
  assert.equal(controller.getSnapshot().release, undefined);
  assert.equal(controller.getSnapshot().preferences.lastChecked, 0);
  assert.equal(controller.getSnapshot().preferences.skippedVersion, "");
  await controller.check(false, UPDATE_INTERVAL);
  assert.deepEqual(channels, ["stable", "beta"]);
});

test("a channel cannot change during an in-flight check", async () => {
  let finish!: () => void;
  const { controller } = setup({ adapter: { check: async () => {
    await new Promise<void>(resolve => { finish = resolve; });
    return { status: "current" };
  } } });
  const pending = controller.check();
  await new Promise(resolve => setImmediate(resolve));
  controller.setChannel("beta");
  assert.equal(controller.getSnapshot().preferences.channel, "stable");
  finish(); await pending;
  assert.equal(controller.getSnapshot().phase, "current");
});

test("channel selection stays locked during download and installation", async () => {
  let finishDownload!: () => void;
  let finishInstall!: () => void;
  const { controller } = setup({ adapter: {
    download: async () => { await new Promise<void>(resolve => { finishDownload = resolve; }); },
    install: async () => { await new Promise<void>(resolve => { finishInstall = resolve; }); },
  } });
  await controller.check();
  const download = controller.download();
  controller.setChannel("beta");
  assert.equal(controller.getSnapshot().preferences.channel, "stable");
  finishDownload(); await download;
  const install = controller.install();
  await new Promise(resolve => setImmediate(resolve));
  controller.setChannel("beta");
  assert.equal(controller.getSnapshot().preferences.channel, "stable");
  finishInstall(); await install;
});

test("native temporary-file failure requires a fresh download", async () => {
  const { controller, calls } = setup({ adapter: { install: async () => { throw { code: "UPDATE_STORAGE", message: "temporary file unavailable" }; } } });
  await controller.check(); await controller.download(); await controller.install();
  assert.equal(controller.getSnapshot().phase, "available");
  await controller.download();
  assert.equal(calls.download, 2);
});

test("unpublished channels have no fabricated release link and remain eligible for later checks", async () => {
  const { controller, calls } = setup({ adapter: { check: async () => ({ status: "unpublished" }) } });
  await controller.check(); await controller.download(); await controller.install();
  assert.equal(controller.getSnapshot().phase, "unpublished");
  assert.equal(controller.getSnapshot().release, undefined);
  assert.equal(controller.getSnapshot().error, undefined);
  assert.equal(calls.install + calls.download, 0);
  controller.setChannel("beta");
  await controller.check();
  assert.equal(controller.getSnapshot().phase, "unpublished");
});

test("installer failures allow a new download instead of reusing consumed installer bytes", async () => {
  const { controller, calls } = setup({ adapter: { install: async () => { throw { code: "UPDATE_INSTALL", message: "installer unavailable" }; } } });
  await controller.check(); await controller.download(); await controller.install();
  assert.equal(controller.getSnapshot().phase, "available");
  assert.equal(controller.getSnapshot().error?.code, "UPDATE_INSTALL");
  await controller.download();
  assert.equal(calls.download, 2);
  assert.equal(controller.getSnapshot().phase, "ready");
});

test("switching channel emits no old ready package and ignores delayed IPC progress", async () => {
  let emit!: Parameters<UpdateAdapter["download"]>[0];
  const { controller } = setup({ adapter: { download: async progress => { emit = progress; progress({ downloaded: 10 }); } } });
  await controller.check(); await controller.download();
  const snapshots: ReturnType<UpdateController["getSnapshot"]>[] = [];
  controller.subscribe(() => snapshots.push(controller.getSnapshot()));
  controller.setChannel("beta");
  emit({ downloaded: 90 });
  assert.equal(snapshots.length, 1);
  assert.equal(snapshots[0].phase, "idle");
  assert.equal(snapshots[0].release, undefined);
  assert.equal(snapshots[0].progress.downloaded, 0);
});
