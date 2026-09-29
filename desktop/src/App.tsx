import { useState } from "react";
import { HarnessProvider, useHarness } from "./state";
import { I18nProvider } from "./core";
import {
  TitleBar,
  Sidebar,
  CanvasGraph,
  LogConsole,
  DiagnosticsPanel,
  PromptConsole,
  DetailDrawer,
  ToolMonitorDrawer,
  LootCard,
  SettingsModal,
  KbNavigator,
} from "./views";
import "./App.css";

function AppContent() {
  const {
    sessions,
    activeSessionId,
    currentSession,
    viewMode,
    steps,
    logs,
    selectedStep,
    deliverables,
    isRunning,
    isToolMonitorOpen,
    executeHarness,
    stopHarness,
    clearLogs,
    newSession,
    selectSession,
    selectStep,
    setViewMode,
    setToolMonitorOpen,
    dismissLoot,
  } = useHarness();

  const [isSettingsOpen, setIsSettingsOpen] = useState(false);

  return (
    <div className="w-screen h-screen bg-[#09090b] text-zinc-100 flex flex-col select-none overflow-hidden font-sans">
      {/* 1. Integrated borderless TitleBar with native dragging & controls */}
      <TitleBar title={currentSession?.target} />

      {/* 2. Decoupled Workspace */}
      <div className="flex-1 flex overflow-hidden relative">
        {/* Left Harness Sidebar */}
        <Sidebar
          sessions={sessions}
          activeSessionId={activeSessionId}
          onSelectSession={selectSession}
          onNewSession={newSession}
          onOpenTools={() => setToolMonitorOpen(true)}
          onOpenSettings={() => setIsSettingsOpen(true)}
          activeView={viewMode}
          onToggleView={setViewMode}
        />

        {/* Center Main Stage with Full-Bleed Canvas + Floating Prompt Console */}
        <div className="flex-1 relative overflow-hidden bg-[#09090b]">
          {/* Swappable Views (Graph | Logs | Diagnostics | KB) Full Bleed */}
          <div className="absolute inset-0 w-full h-full overflow-hidden">
            {viewMode === "canvas" && (
              <CanvasGraph
                steps={steps}
                selectedStep={selectedStep}
                onSelectStep={selectStep}
              />
            )}
            {viewMode === "console" && (
              <LogConsole
                logs={logs}
                onClear={clearLogs}
              />
            )}
            {viewMode === "diagnostics" && (
              <DiagnosticsPanel
                currentTarget={currentSession?.target}
              />
            )}
            {viewMode === "kb" && (
              <KbNavigator
                onSelectTechnique={(ref) => {
                  executeHarness(currentSession?.target || "target.bin", `深入参考 ${ref} 并执行针对性逆向`, "wish");
                  setViewMode("canvas");
                }}
              />
            )}
          </div>

          {/* Floating Prompt Console on Top of Grid Dots */}
          <div className="absolute bottom-4 left-0 right-0 z-20 pointer-events-none px-4">
            <div className="pointer-events-auto max-w-2xl mx-auto">
              <PromptConsole
                isRunning={isRunning}
                defaultTarget={currentSession?.target}
                onExecute={executeHarness}
                onStop={stopHarness}
              />
            </div>
          </div>
        </div>

        {/* Drawers & Overlays */}
        <DetailDrawer
          step={selectedStep}
          onClose={() => selectStep(null)}
        />

        <ToolMonitorDrawer
          isOpen={isToolMonitorOpen}
          onClose={() => setToolMonitorOpen(false)}
        />

        {deliverables && (
          <LootCard
            deliverables={deliverables}
            onClose={dismissLoot}
          />
        )}

        <SettingsModal
          isOpen={isSettingsOpen}
          onClose={() => setIsSettingsOpen(false)}
        />
      </div>
    </div>
  );
}

export default function App() {
  return (
    <I18nProvider>
      <HarnessProvider>
        <AppContent />
      </HarnessProvider>
    </I18nProvider>
  );
}
