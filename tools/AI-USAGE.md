# Tools AI Usage

AI 使用工具时的约定。

## 规则

- 工具路径统一从 `tools/` 出发
- 首次使用前检查工具是否已安装
- GUI 工具默认不自动启动，除非用户明确要求
- 优先使用命令行/headless 模式
- 工具输出放入 `exports/<board>/`
