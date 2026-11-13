# Evidence Checklist

For every meaningful finding, capture:

- Full request and response.
- Timestamp and target URL.
- Cookie/session identity used.
- Payload and exact encoding.
- Server-side visible effect: error, file content, row count, flag, callback, state change.
- Tool command or script path.
- If browser-side: screenshot, network trace, JS hook output, storage/cookie snapshot.
- If race: number of requests, timing, success/failure ratio.

Evidence is stronger when it is replayable from a clean session.
