<script setup lang="ts">
import TelemetryBar from './components/TelemetryBar.vue'
import HeroSection from './components/HeroSection.vue'
import PipelineSection from './components/PipelineSection.vue'
import BoardsSection from './components/BoardsSection.vue'
import DesktopSection from './components/DesktopSection.vue'
import McpWorkbench from './components/McpWorkbench.vue'
import TerminalSection from './components/TerminalSection.vue'
import RepoScriptsSection from './components/RepoScriptsSection.vue'
import CommunitySection from './components/CommunitySection.vue'
</script>

<template>
  <div class="rl-bench">
    <!-- 01. Telemetry & Live Status -->
    <TelemetryBar />

    <!-- 02. Precision Laboratory Hero & Gauges -->
    <HeroSection />

    <!-- 03. 5-Stage Reversing Pipeline Loop -->
    <PipelineSection />

    <!-- 04. 5 Attack Boards Matrix -->
    <BoardsSection />

    <!-- 05. Desktop Visual Workbench (Branch: dev) -->
    <DesktopSection />

    <!-- 06. Agent MCP Tool Matrix & JSON-RPC Inspector -->
    <McpWorkbench />

    <!-- 07. Multi-Platform Setup Terminal -->
    <TerminalSection />

    <!-- 08. Maintainer & Automation Tooling -->
    <RepoScriptsSection />

    <!-- 09. Star History & Open Source Community -->
    <CommunitySection />
  </div>
</template>

<style scoped>
.rl-bench {
  max-width: 1160px;
  margin: 0 auto;
  padding: 0 24px 80px;
}
</style>
