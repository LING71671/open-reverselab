# Desktop UI design

Mode: Operate. The main task is to select a workspace and target, start a Goal, and inspect progress or evidence without taking over routine agent decisions.

## Visual direction

Use the OFFFOLD neutral palette, verified from the user's brand site. Light: canvas `#ffffff`, surface `#f3f3f3`, line `#dfdfdf`, ink `#151515`, secondary `#676767`. Dark: canvas `#141414`, surface `#212121`, line `#363636`, ink `#f2f2f2`, secondary `#aaaaaa`.

The title bar displays only the ReverseLab symbol and wordmark. Use a 22 px symbol, 18 px wordmark, a 10 px gap and a 52 px title bar. Its background continues the sidebar surface without a horizontal divider through the brand area.

Google Material 3 is the reference for type roles, pane behavior, component states and motion. Adapt it to a desktop harness and the OFFFOLD palette. The user explicitly prefers restrained type over enlarged bold headlines; empty Goals have no decorative heading. Reference: [type roles](https://m3.material.io/styles/typography/applying-type), [pane layouts](https://m3.material.io/foundations/layout/applying-layout/pane-layouts), [motion](https://m3.material.io/styles/motion). Use Material's functional standard motion direction, without decorative bounce.

Red and blue are limited track accents. Status colors carry meaning and accompany text or icons. The page is not tinted by the selected track. Fonts use a local system stack with Chinese fallbacks; code and paths use monospace.

## Layout and components

The upper-left `red / blue / both` control is a styled radio group. Below it are the workspace selector and New Goal action. Navigation separates Goals, samples, knowledge, logs and health. A Goal has two retained views: document and canvas. Document is the default reading surface; both share the same task and composer. The composer occupies its own resizable pane below the content. Sidebars and detail panes are also resizable.

- Type roles: page title 22/28, section title 16/24, controls 14/20, prose 16/28, metadata 12/18. Body prose uses regular weight; controls and section titles use medium weight. Running task titles use a compact 15px medium style. Use the system sans-serif with explicit Chinese UI fallbacks; reserve monospace for code, paths and measurements. Spacing uses a 4px base and 8px group rhythm.
- Use 6–11px corner radii, thin neutral borders and clear spacing. Avoid repeated decorative cards, gradient backgrounds, glowing status ornaments, marketing text and fake dashboard numbers.
- Buttons and dropdowns use the same font, border, hover and focus treatment. Current selection must be visible. Icon-only actions require names and tooltips.
- Settings, workspace and tools use full pages with a fixed navigation pane and flexible content pane. Selection menus are custom, accessible controls. Deletion uses an inline confirmation. Do not use native alert/confirm/validation balloons. File/directory selection in desktop uses the native picker. Browser preview accepts explicit local paths.
- Empty canvas shows the core Goal label. Empty states contain only necessary state and actions.
- Optional time/Token limits expand in place and default to unlimited. Enter creates a new line; Ctrl/Cmd+Enter submits. Incomplete empty drafts stay inactive without a validation balloon.
- Show actual pending/running/error states. Errors stay adjacent to the action or result they affect, with retry where meaningful.
- Workflow follow mode is explicit. Manual pan or node drag disables following; users can fit the graph or resume following. Node positions survive status updates.
- Canvas nodes expand inline to show details, then collapse without losing selection. Expansion reflows nearby nodes. Fullscreen uses the available app viewport, keeps zoom/pan controls, and exits with Escape. Full execution evidence remains available through an explicit detail action. Only runtime relationships appear as branches and joins.
- Documents use a master/detail reader, search, domain filter and paired references. Internal Markdown links stay inside the knowledge view.
- Mount pages on first visit and retain them when navigating away. Preserve document scroll, search, filters and disclosures within the active workspace; hidden views must not receive keyboard focus, file drops or camera updates. Keep unsubmitted Goal drafts and optional limits by task/track for the current workspace session. Track switching restores that track's last selected task.
- Cache up to 40 opened documents in memory; refreshing the knowledge library clears this cache. Show domain names in the reader toolbar and an explicit Create Goal action. Horizontally scroll wide tables instead of squeezing Chinese text into single-character columns.
- Use plain action and state labels: target is labelled “目标”, the objective asks “描述要完成的任务”, and unknown health observations say “暂无记录”. Do not repeat the current track beside every page heading or show a task status on unrelated library pages.

## Motion

Use a 180ms moving selection surface for the track radio group and scoped theme color transitions. Page changes use a 140ms opacity transition without moving the layout. Keep 150–250ms motion for expanding controls and canvas navigation. Spinners indicate actual pending work; skeleton rows indicate unknown document content, never a cached document. Honor `prefers-reduced-motion`, including canvas camera and activity scrolling. No animated decoration or fake progress percentages.

## Review requirements

Inspect both themes at the shipped desktop size. Check radio switching, custom dropdowns, form and menu keyboard behavior, document overflow, retained views, fullscreen restoration, node expansion, task cancellation, concurrent task selection and error states. Only real runtime events may appear as successful observations.
