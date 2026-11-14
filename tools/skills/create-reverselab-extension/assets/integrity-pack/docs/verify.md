# Verify file integrity

Check where the declared digest came from and which artifact version it covers. Compare the current file digest independently, then reference the comparison evidence and the declaration source in the result.

A matching digest from a documented reference supports integrity relative to that reference. If the source is unknown, report the byte comparison and keep the source check unresolved. A mismatch identifies a different artifact; it does not identify why the bytes differ.
