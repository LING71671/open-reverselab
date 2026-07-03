const $ = (selector) => document.querySelector(selector)
const state = {
  ctx: null,
  currentTechnique: null,
  mcpMapping: [],
}

async function api(path) {
  const response = await fetch(path)
  const data = await response.json()
  if (!response.ok) throw new Error(data.error || response.statusText)
  return data
}

async function postApi(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  })
  const data = await response.json()
  if (!response.ok) throw new Error(data.error || response.statusText)
  return data
}

function renderRuntime(ctx) {
  $("#runtime").innerHTML = `
    <dt>Root</dt><dd>${escapeHtml(ctx.root)}</dd>
    <dt>Board</dt><dd>${escapeHtml(ctx.board)}</dd>
    <dt>OpenCode</dt><dd>${ctx.opencodeConfigExists ? "config ready" : "config pending"}</dd>
    <dt>Runtime</dt><dd>${escapeHtml(ctx.opencodeUrl || "")}</dd>
  `
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
}

function renderResults(results) {
  if (!results.length) {
    $("#routeResults").innerHTML = `<div class="result-item">没有命中。换一个更宽的信号，或先看 attack-network。</div>`
    return
  }
  $("#routeResults").innerHTML = results
    .map(
      (item) => `
        <article class="result-item">
          <strong>${escapeHtml(item.id || "(unknown)")}</strong>
          <div class="result-meta">score=${item.score} priority=${item.priority ?? 0}</div>
          <div>${(item.signals || []).slice(0, 6).map(escapeHtml).join(", ")}</div>
          ${(item.files || [])
            .map(
              (file) => `
                <button class="file-button" data-technique="${escapeHtml(file.path)}">
                  ${file.exists ? "✓" : "✗"} ${escapeHtml(file.display)}
                </button>
              `,
            )
            .join("")}
        </article>
      `,
    )
    .join("")
  document.querySelectorAll("[data-technique]").forEach((button) => {
    button.addEventListener("click", () => loadTechnique(button.dataset.technique))
  })
}

function renderMapping(mapping) {
  state.mcpMapping = mapping || []
  if (!state.mcpMapping.length) {
    $("#mcpMapping").innerHTML = `<div class="result-item">选择技术文件后显示 MCP 工具映射。</div>`
    return
  }
  $("#mcpMapping").innerHTML = state.mcpMapping
    .map(
      (item) => `
        <article class="mapping-item">
          <strong>${escapeHtml(item.step)}</strong>
          <code>${escapeHtml(item.command)}</code>
          <p>${escapeHtml(item.description)}</p>
          ${
            item.runnable
              ? `<button class="secondary mapping-run" data-tool="${escapeHtml(item.ctfTool)}">填入 ${escapeHtml(item.ctfTool)}</button>`
              : ""
          }
        </article>
      `,
    )
    .join("")
  document.querySelectorAll(".mapping-run").forEach((button) => {
    button.addEventListener("click", () => {
      $("#toolName").value = button.dataset.tool
      $("#toolArgs").focus()
    })
  })
}

async function routeSignal() {
  const signal = $("#signal").value.trim()
  if (!signal) return
  $("#routeResults").innerHTML = `<div class="result-item">Routing...</div>`
  $("#rawOutput").textContent = ""
  try {
    const data = await api(`/api/kb-route?signal=${encodeURIComponent(signal)}`)
    renderResults(data.results)
    $("#rawOutput").textContent = `${data.raw.stdout || ""}${data.raw.stderr || ""}`
  } catch (error) {
    $("#routeResults").innerHTML = `<div class="result-item">${escapeHtml(error.message)}</div>`
  }
}

async function loadTechnique(path) {
  $("#techniqueTitle").textContent = path
  $("#techniqueContent").textContent = "Loading..."
  renderMapping([])
  try {
    const data = await api(`/api/technique?path=${encodeURIComponent(path)}`)
    state.currentTechnique = data
    $("#techniqueTitle").textContent = data.path
    $("#techniqueContent").textContent = data.content
    renderMapping(data.mcpMapping || [])
  } catch (error) {
    $("#techniqueContent").textContent = error.message
  }
}

async function loadToolStatus() {
  $("#toolOutput").textContent = "Checking tools..."
  try {
    const data = await api("/api/ctf-tool-status")
    $("#toolOutput").textContent = JSON.stringify(data, null, 2)
  } catch (error) {
    $("#toolOutput").textContent = error.message
  }
}

async function runTool() {
  const tool = $("#toolName").value
  const args = $("#toolArgs").value.trim()
  $("#toolOutput").textContent = `Running ${tool}...`
  try {
    const data = await postApi("/api/run-ctf-tool", {
      caseName: $("#caseName").value,
      tool,
      args,
      timeout: 120,
    })
    $("#toolOutput").textContent = JSON.stringify(data, null, 2)
    await loadArtifacts()
  } catch (error) {
    $("#toolOutput").textContent = error.message
  }
}

async function buildHandoff() {
  $("#handoffPrompt").textContent = "Building handoff..."
  try {
    const data = await postApi("/api/ai-handoff", {
      caseName: $("#caseName").value,
      target: $("#target").value,
      signal: $("#signal").value,
      techniquePath: state.currentTechnique?.path || "",
      mapping: state.mcpMapping,
    })
    $("#handoffPrompt").textContent = `${data.prompt}\n\nSaved: ${data.note}`
    await loadArtifacts()
  } catch (error) {
    $("#handoffPrompt").textContent = error.message
  }
}

async function loadArtifacts() {
  const data = await api("/api/artifacts")
  $("#artifacts").innerHTML = Object.entries(data)
    .map(
      ([name, items]) => `
        <div class="artifact-column">
          <h4>${escapeHtml(name)}</h4>
          ${
            items.length
              ? items
                  .slice(0, 20)
                  .map((item) => `<div class="artifact">${escapeHtml(item.path)}<br>${item.size} bytes</div>`)
                  .join("")
              : `<div class="artifact">empty</div>`
          }
        </div>
      `,
    )
    .join("")
}

async function init() {
  const [ctx, docs] = await Promise.all([api("/api/context"), api("/api/bootstrap-docs")])
  state.ctx = ctx
  renderRuntime(ctx)
  renderMapping([])
  $("#attackNetwork").textContent = docs.attackNetwork
  await loadArtifacts()
  $("#routeBtn").addEventListener("click", routeSignal)
  $("#refreshArtifacts").addEventListener("click", loadArtifacts)
  $("#refreshTools").addEventListener("click", loadToolStatus)
  $("#runTool").addEventListener("click", runTool)
  $("#buildHandoff").addEventListener("click", buildHandoff)
  $("#signal").addEventListener("keydown", (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === "Enter") routeSignal()
  })
}

init().catch((error) => {
  document.body.innerHTML = `<pre>${escapeHtml(error.stack || error.message)}</pre>`
})
