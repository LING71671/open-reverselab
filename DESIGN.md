# Design

> ReverseLab 站点设计规范。配套 [PRODUCT.md](PRODUCT.md) 使用：品牌首页（brand register）+ 知识库文档区（product register）。

## Overview

**氛围场景**：无影灯下的精密实验室工作台，校准过的仪表、排列整齐的样本编号、可追溯的每一步操作。浅色、安静、高信息密度，锐利感来自排版秩序与克制的强调色，不来自装饰。

**策略**：Restrained（克制的中性色 + 一个深靛主色 + 琥珀点缀 ≤10%）。纯白底，颜色只出现在"有意义"的地方（链接、状态、板块识别）。

## Colors

OKLCH 全部。主色取种子 hue 280° 但压到深靛墨色（避开 AI-purple-on-white 吸引子），accent 用琥珀校准色（安全工具状态灯气质）。

```css
:root {
  --bg:        oklch(1.000 0.000 0);        /* 纯白 */
  --surface:   oklch(0.965 0.003 280);      /* 卡片/面板，极浅冷紫灰 */
  --surface-2: oklch(0.945 0.005 280);      /* 次级面板/代码块底 */
  --ink:       oklch(0.160 0.020 280);      /* 正文，近黑墨色（≥12:1 vs bg）*/
  --ink-soft:  oklch(0.300 0.020 280);      /* 次级正文（≥7:1）*/
  --muted:     oklch(0.500 0.015 280);      /* 辅助文字（≥4.5:1）*/
  --line:      oklch(0.900 0.004 280);      /* 分隔线/描边 */
  --primary:   oklch(0.420 0.140 278);      /* 深靛墨蓝紫：链接、标题强调、主按钮（白字）*/
  --primary-2: oklch(0.340 0.130 280);      /* 主色 hover/按压 */
  --primary-soft: oklch(0.955 0.020 280);   /* 主色浅底（选中态/标签底，配 --primary 文字）*/
  --accent:    oklch(0.580 0.150 65);       /* 琥珀校准色：状态点、徽章、亮点（≤10% 面积）*/
  --accent-soft: oklch(0.960 0.030 65);     /* 琥珀浅底 */
  --ok:        oklch(0.520 0.140 150);      /* 语义绿：MCP/工具 PASS 状态 */
  --warn:      oklch(0.620 0.150 75);       /* 语义琥珀：WARN */
  --danger:    oklch(0.520 0.190 25);       /* 语义红：FAIL */
  --code-bg:   oklch(0.160 0.020 280);      /* 代码块深底（浅色文档站中代码块保持深色）*/
}
```

约束：正文对比 ≥4.5:1（`--muted` 即下限）；主色填充一律白字（L 0.42 饱和色，Helmholtz-Kohlrausch）；语义色只做状态不承载正文；禁止渐变文字/玻璃拟态。

## Typography

字体族 3 个封顶：**IBM Plex Sans**（标题，瑞士工程手册气质）+ 系统 UI 栈（正文，性能与可读性）+ **JetBrains Mono**（代码）。

```css
--font-display: "IBM Plex Sans", "Segoe UI", system-ui, sans-serif;
--font-body:    system-ui, "Segoe UI", "PingFang SC", "Microsoft YaHei", sans-serif;
--font-mono:    "JetBrains Mono", ui-monospace, "Cascadia Code", Consolas, monospace;
```

- 标题层级比例 ≥1.25：display clamp(2.25rem, 5vw, 3.5rem)（≤6rem 上限，字距 ≥-0.02em，不做 -0.04 以下的挤字）
- h1-h3 用 `text-wrap: balance`，长文用 `text-wrap: pretty`
- 正文行宽 65-75ch
- 大写字母仅用于短标签（≤4 词）与徽章；不用全大写正文
- 中文正文用系统黑体栈，数字/英文/代码用对应西文字体，`font-variant-numeric: tabular-nums`

## Components

- **板块徽章**（board badge）：5 大板块各一个命名色相（CTF=靛、APK=青、PE=琥珀、General=绿、Windows=紫灰），浅底 + 深色文字，用于文章标签/卡片/目录树。徽章只做小尺寸，不承载正文。
- **状态点**（status dot）：MCP 工具/检查项 PASS/WARN/FAIL，`--ok/--warn/--danger` 圆点 + 文字，不只靠颜色（配 ✓/!/✗ 符号）。
- **链接**：`--primary` 下划线（hover 加粗），避免"看起来像正文"的链接。
- **代码块**：深底 `--code-bg` + 浅色语法，文件头（路径 + 语言徽章），复制按钮。
- **按钮**：主按钮 = 实心 `--primary` 白字（label 动词+宾语）；次按钮 = 1px `--line` 描边无阴影。禁止 1px 边框 + 16px 以上大阴影的组合。
- **卡片**：圆角 ≤12px，1px `--line` 描边 **或** ≤8px 阴影，二选一；避免同尺寸图标+标题+文本三件套的重复卡片（首页板块用编号表格/非对称布局）。
- **侧栏**：文档区左侧目录树，当前项 `--primary-soft` 底 + `--primary` 文字；无左侧色条（禁止 side-stripe）。

## Layout

- 首页（brand）：导航 → hero（一句话定位 + 行动按钮，无大数字模板）→ 板块目录（5 板块，编号 + 文章数 + 入口）→ MCP 工具生态（分组表格/列表）→ 快速开始（代码块）→ 页脚。
- 文档区（product）：VitePress 默认骨架定制——顶导航（板块切换）、左侧目录树（按 kb/ 目录结构自动生成，根治旧站索引缺失）、移动端抽屉、正文 + 右侧 on-this-page。
- 响应式：`repeat(auto-fit, minmax(280px, 1fr))` 免断点网格；目录树 <960px 收抽屉。
- 语义 z-index：dropdown(10) → sticky(20) → modal-backdrop(30) → modal(40) → toast(50) → tooltip(60)。

## Motion

克制。只做：hover 颜色/下划线过渡（150-200ms，ease-out）；板块列表 stagger 入场（transform+opacity，250ms，间隔 60ms，仅首页一次）；滚动 reveal 使用 intersection 触发但**内容默认可见**（不 gate 可见性，headless 渲染不丢内容）。禁止：弹跳、弹性、背景粒子、数字滚动动画。全部动画配 `@media (prefers-reduced-motion: reduce)` 降级为瞬时。

## Accessibility

WCAG AA：正文 ≥4.5:1（调色板已内建）；键盘全导航（目录树/搜索/按钮 focus ring 用 `--primary` 2px）；`prefers-reduced-motion` 全面降级；状态不只靠颜色；代码块可横向滚动且有可见滚动条；搜索支持键盘操作。中英文混排注意行高（中文 1.6-1.7）。

## Assets

- 品牌标识：纯文字 logo（"ReverseLab" 等宽风格标识，`--font-mono` + 状态点），暂不做图形 logo；favicon 用主色方块 + 白点。
- 社交图：`assets/social-preview.png` 需按新设计重制（1200×630，白底 + 深靛标题 + 板块徽章）。

## References

- 安全工具站参考（用户指定方向）：PortSwigger Web Security Academy（学院蓝、浅色、高信息密度）、ProjectDiscovery 文档站（浅色、状态点、工具表格）、HackTricks（目录优先）。
- 反参考（用户明确排除）：黑客绿/矩阵、SaaS 紫蓝渐变、旧站手工简陋风、发布会炫技动效。
