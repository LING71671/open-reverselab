# Inspect a digest claim

Compare the observed SHA256 with the declared 64-character hexadecimal SHA256. Preserve both values and the declaration source. Report a match or mismatch for that exact file revision. If the claim has the wrong format or the observed digest is missing, leave the comparison unresolved and identify the missing input.

This method evaluates a claim. It does not modify the file or produce a new reference digest.
