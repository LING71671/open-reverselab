# AI Manifest Schema

Case 目录的 AI 可读索引文件结构说明。

## manifest.json 格式

```json
{
  "case_id": "",
  "board": "",
  "status": "",
  "created": "",
  "updated": "",
  "targets": [],
  "files": {
    "samples": [],
    "projects": [],
    "exports": [],
    "notes": [],
    "reports": [],
    "patches": [],
    "scripts": []
  },
  "findings": [],
  "open_questions": []
}
```

AI 进入 case 目录后应首先读取此文件以获取全局视图。
