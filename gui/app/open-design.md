# OpenDesign Architecture

ReverseLab GUI uses an OpenDesign-style split:

```text
ReverseLab GUI product
  -> OpenCode runtime adapter
    -> AI provider API
    -> ReverseLab MCP
      -> kb / scripts / tools
      -> exports / notes / reports
```

## Ownership

- ReverseLab owns the product UI, workflow, packaging, domain copy, and board-specific screens.
- OpenCode provides AI runtime capabilities: provider connections, sessions, MCP/tool-call plumbing, and local server APIs.
- ReverseLab MCP and scripts remain the source of truth for actual CTF, APK, PE, and general analysis logic.

## Runtime Rules

- GUI launches OpenCode automatically.
- GUI generates local OpenCode config from the selected workspace path.
- GUI defaults to the `reverselab-ctf` agent for V1.
- Local execution is unrestricted for authorized lab work.
- Provider-side policy/API behavior is the review boundary.
- The app listens on loopback only unless the user explicitly changes it.

## Packaging Rules

- Packaged app opens directly to ReverseLab GUI.
- OpenCode is bundled or discovered as a runtime dependency.
- User data lives outside bundled app files.
- Public releases must not include private cases, samples, credentials, or user-specific absolute paths.

