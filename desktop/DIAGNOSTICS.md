# Diagnostics

[简体中文](DIAGNOSTICS.zh-CN.md) · [Desktop guide](README.md)

**Settings → Diagnostics** has two independent switches: **Performance warnings** and **Send diagnostic data**. Both default to off. Preferences are stored locally and apply across workspaces.

## Performance warnings

Enable **Performance warnings** in the desktop app to detect sustained UI stalls or high resource use. Normal operation adds no persistent status strip. A warning appears only when an observed condition persists; it does not stop Goals or reduce their concurrency.

The default policy in [diagnostics.config.json](diagnostics.config.json) samples about every two seconds and requires an abnormal condition to persist for at least 15 seconds:

| Condition | Threshold |
| --- | --- |
| High CPU use | 90% of the available logical processors |
| High memory use | 2 GiB of combined resident working sets |
| Slow UI response | An animation-frame gap of at least 250 ms in successive sampling intervals |

CPU and memory include Open ReverseLab and its descendant processes, such as WebView and Python children. CPU needs two observations before a percentage is available. Memory totals may count shared pages more than once. Animation-frame gaps measure UI responsiveness.

**Dismiss this warning** hides the current condition until it recovers; monitoring remains enabled. Hiding the window pauses collection and clears the current warning. Showing it resumes with fresh observations. Turning the setting off cancels timers and animation-frame callbacks and releases the native sampler. CPU, memory, and frame-gap samples are not saved or uploaded. Browser preview does not collect native process samples.

## Remote error and timing reports

**Send diagnostic data** enables optional Sentry reporting when the build includes a valid `VITE_SENTRY_DSN`. The switch is unavailable in builds without a diagnostic endpoint. Sentry reporting does not enable local performance monitoring.

Only new runtime events are eligible after the switch is enabled. Opening a stored Goal or rebuilding its health view does not upload its history. Reports contain the following fields:

| Report | Included data |
| --- | --- |
| Runtime failure | An established error code and its layer, such as model, tool, or storage |
| Unhandled UI error | `UI_UNHANDLED`, a standard error type, and stack locations limited to application build assets |
| Operation timing | A generic layer name such as `operation.tool`, timing, status, and generated trace identifiers |
| Common metadata | Application version, build environment, event identifier, and timestamp |

The sanitizer removes samples, targets, prompts, file paths, credentials, raw error messages, tool output, user information, and arbitrary event fields. IP inference is disabled and an empty location field prevents server-side location enrichment. Automatic session replay, breadcrumbs, and request instrumentation are disabled.

The default operation-timing sample rate is 10%, defined by `remote.traceSampleRate` in [diagnostics.config.json](diagnostics.config.json). Setting it to `0` disables timing reports while retaining error reporting when the user has enabled diagnostics.

Turning **Send diagnostic data** off removes the event listeners, disconnects the runtime receiver, closes the SDK, and aborts in-flight submissions. Previously received events remain with the configured Sentry project. Diagnostic delivery failures do not interrupt a Goal. The [proxy pool](NETWORK.md) controls model and Python routes; Sentry uses the WebView's network configuration.

## Build configuration and checks

Set `VITE_SENTRY_DSN` to the project's public ingestion DSN when building a distribution that supports remote diagnostics. Keep Sentry management/authentication tokens out of `VITE_*` variables and frontend code. Keep `remote.enabled` false so reporting remains a user choice.

The local [diagnostics policy tests](tests/diagnostics.test.ts) cover defaults, sustained warnings, preference handling, and historical-event isolation. The [SDK transport test](tests/telemetryTransport.test.mjs) checks serialized envelopes from the installed Sentry SDK, sanitization, cancellation, and enable/disable races with a synthetic transport. Live project delivery and its server-side fields require a separate check against that build's diagnostic endpoint.
