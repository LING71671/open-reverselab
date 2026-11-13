# Frequently asked questions

## What does ReverseLab include?

A desktop workspace, a red/blue knowledge base, and CLI/MCP tools for external AI clients. The desktop runs target-bound Goals and displays execution branches, evidence, verification, and reports. Knowledge areas include Web, APK, PE, cryptography, and protocols.

## Where do I download the desktop?

Download the Windows x64 installer from [v2.0.0 Releases](https://github.com/LING71671/open-reverselab/releases/tag/v2.0.0) and run it. Installed builds support signed updates in Settings. Python 3.10+ and WebView2 Runtime are required. For the portable ZIP, extract everything and keep `kb/` and `scripts/` beside the application.

macOS/Linux retain the CLI/MCP workflow; this release has no native desktop binaries for them. See the [desktop guide](https://github.com/LING71671/open-reverselab/blob/main/desktop/README.md).

## What do red, blue, and both mean?

Red and blue use independent strategies. Both runs two parallel branches and joins their results. In the KB, `both` marks shared documents; attack and defense articles link through relationship metadata. Desktop selection does not change an external MCP client's mode.

## Do I need to set a budget?

No. Defaults are 10 minutes and 32,000 tokens per Goal. Optional controls change these limits. Failed routes, repeated scripts, and evidence changes feed back into planning. Independent verification decides completion; exhaustion, cancellation, and blocked routes retain distinct states.

## Can tasks run concurrently?

Each workspace runs two Goals concurrently by default and queues the remainder. A both Goal has red and blue branches. Switching tasks or workspaces preserves output ownership. Closing the app interrupts execution; history is restored next time, and continuation requires a new Goal.

## Where do files and model data go?

The default workspace is `~/.open-reverselab/workspaces/Default`, or you can choose another directory. Originals, work copies, records, and reports live in its `.reverselab/` directory. Model-assisted tasks send context and selected evidence to the configured endpoint. API keys are held in WebView local storage, without operating-system keychain integration.

## Does the desktop call every MCP tool automatically?

Its current adapter runs bounded Python observations. Tools named in KB articles require corresponding adapters and local installation. External AI clients can call the MCP server separately. Python actions run with the user's permissions; the application does not provide an operating-system sandbox.

## How do I check installation and contribute?

Use `START_HERE.bat` on Windows or `./START_HERE.sh` on macOS/Linux for CLI/MCP checks. Run relevant tests and `python scripts/misc/public_release_check.py` for changes. See [Contributing](https://github.com/LING71671/open-reverselab/blob/main/.github/CONTRIBUTING.md).
