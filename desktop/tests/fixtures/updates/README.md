# Updater download fixture

`payload.txt` is plain text signed for synthetic version `9.9.9`. The test serves
it from a loopback HTTP server and calls the same official Tauri download and
signature verification path used by the application. It never calls installation.
The public key is only for this fixture; the corresponding private key is not
included and is unrelated to the application release key.

The test verifies a valid payload, modified content, an announced version that
differs from the signed version, and a failed HTTP download. Keep the payload's
LF line ending unchanged because its bytes are signed. To replace the fixture,
generate a disposable key with `pnpm tauri signer generate`, sign the text with
`pnpm tauri signer sign --app-version 9.9.9`, and retain only the public key,
payload, and signature here.
