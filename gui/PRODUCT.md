# Product

## Register

product

## Users

ReverseLab GUI is for technical users doing authorized CTF, reverse engineering, malware behavior review, protocol analysis, and binary triage. They are already comfortable with tools, evidence, scripts, and AI agents, but they need the workflow to be visible and repeatable instead of buried in chat history or terminal output.

## Product Purpose

ReverseLab GUI makes the existing ReverseLab route operable as a local app. The first version focuses on the CTF Website workbench: read the same context files, route signals through the existing knowledge base, open technique files, surface MCP/tool mappings, and keep evidence in the existing `exports/`, `notes/`, and `reports/` directories.

OpenCode is a runtime dependency for AI providers, sessions, MCP, and tool calls. ReverseLab remains the visible product, owns the workflow, and preserves the knowledge base and routing mechanics.

## Brand Personality

Technical, direct, evidence-led. The product should feel like a serious operator console: dense enough for expert work, calm enough for long sessions, and explicit about what route or tool produced each conclusion.

## Anti-references

Do not make this a generic AI chat wrapper, a marketing landing page, or an OpenCode-branded fork as the user-facing product. Avoid decorative dashboard visuals, vague automation claims, and UI patterns that hide the actual ReverseLab route.

## Design Principles

- Preserve the route: GUI actions must map back to `AI-USAGE.md`, board instructions, `kb_router`, technique files, MCP mappings, and evidence directories.
- Show evidence before confidence: every recommendation should expose its source file, command output, or artifact path.
- Keep the first screen task-ready: the CTF workbench should be usable without reading product copy or OpenCode internals.
- Use light infrastructure: prefer a local static UI plus thin bridge before heavier desktop frameworks.
- Package without changing the lab: the app should open directly while keeping user evidence and public repository files separate.

## Accessibility & Inclusion

Target WCAG AA contrast for text and controls. Use system fonts, visible focus states, keyboard-accessible controls, and reduced-motion-friendly interactions. Dense expert UI is acceptable, but labels and route state must remain readable on common laptop screens.
