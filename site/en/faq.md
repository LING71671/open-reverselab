# Frequently asked questions

## What does Open ReverseLab include?

A desktop workspace, a red/blue knowledge base, and CLI/MCP tools for external AI clients. The desktop runs target-bound Goals and displays execution branches, evidence, verification, and reports. Knowledge areas include Web, APK, PE, cryptography, and protocols.

## Where do I download the desktop?

The `v2.0.0-beta.1` desktop packages have been withdrawn while desktop and knowledge-base distribution are separated. A replacement package is not yet published. You can [run from source](./desktop.md#run-from-source); see the [desktop guide](./desktop.md) for configuration.

macOS/Linux retain the CLI/MCP workflow; native desktop packages for them are not currently provided. See the [desktop guide](https://github.com/LING71671/open-reverselab/blob/main/desktop/README.md).

## What do red, blue, and both mean?

Red and blue use independent strategies. Both lets each strategy plan multiple actions, exchange evidence during execution, and assess its own responsibilities before combined verification. In the KB, `both` marks shared documents; attack and defense articles link through relationship metadata. Desktop selection does not change an external MCP client's mode.

## Do I need to set a budget?

No. Goals have no time or token limit by default. Set either value under Run limits when needed; an empty field remains unlimited. Failed routes, repeated scripts, and evidence changes feed back into planning. Independent verification decides completion; reaching a configured limit, cancellation, and blocked routes retain distinct states.

## Can tasks run concurrently?

Each workspace supports concurrent Goals without an application-level count limit. Red and blue can each plan multiple actions within a both Goal; independent actions start together, while dependent actions wait for their prerequisites. Switching tasks or workspaces preserves output ownership. Closing the app interrupts execution; history is restored next time, and continuation requires a new Goal.

## Where do files and model data go?

The default workspace is `~/.open-reverselab/workspaces/Default`, or you can choose another directory. Originals, work copies, records, and reports live in its `.reverselab/` directory. Model-assisted tasks send context and selected evidence to the configured endpoint. API keys are held in WebView local storage, without operating-system keychain integration.

## Does the desktop call every MCP tool automatically?

Its current adapters run target triage and Python actions without a default tool time limit. Tools named in KB articles require corresponding adapters and local installation. External AI clients can call the MCP server separately. Python actions run with the user's permissions; the application does not provide an operating-system sandbox.

## How do I check installation and contribute?

Use `START_HERE.bat` on Windows or `./START_HERE.sh` on macOS/Linux for CLI/MCP checks. Run relevant tests and `python scripts/misc/public_release_check.py` for changes. See [Contributing](https://github.com/LING71671/open-reverselab/blob/main/.github/CONTRIBUTING.md).
