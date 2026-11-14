# Read exact bytes

Read the selected file in binary mode and compute its SHA256 without rewriting it. Record the file revision and byte count alongside the digest. A failed read produces an error, not an empty-file digest.

Python 3.11+ example, with the selected file passed as the first argument:

```python
import hashlib
from pathlib import Path
import sys

data = Path(sys.argv[1]).read_bytes()
print({"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
```

The output is an observation about the bytes read. Re-read after a file revision changes before using it in another comparison.
