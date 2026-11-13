import { useMemo, useEffect, useLayoutEffect, useCallback, useRef, useState } from "react";
import { ReactFlow, Background, MiniMap, useReactFlow, ReactFlowProvider, BackgroundVariant, useNodesState, useNodesInitialized, type Node, type Edge, type NodeChange } from "@xyflow/react";
import { Focus, Scan, Maximize2, Minimize2, Plus, Minus, Map as MapIcon } from "lucide-react";
import { HarnessNode, type HarnessNodeData } from "./nodes/HarnessNode";
import type { GraphStep } from "../../core";
import { reconcileNodes, planNodeMotion, applyNodeMotion, type Point } from "./nodeMotion";
import { layoutGraph, expandLayout, parentIds, edgePorts } from "./graphLayout";
import "./canvas.css";
interface CanvasGraphProps { active: boolean; fullscreen?: boolean; onToggleFullscreen?: () => void; steps: GraphStep[]; selectedStep: GraphStep | null; onSelectStep: (step: GraphStep) => void }
const nodeTypes = { harnessNode: HarnessNode };
const motionDuration = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches ? 0 : 240;
function FlowInner({ active, fullscreen, onToggleFullscreen, steps, selectedStep, onSelectStep }: CanvasGraphProps) {
  const { fitView, zoomIn, zoomOut } = useReactFlow();
  const initialized = useNodesInitialized();
  const [following, setFollowing] = useState(true);
  const [showMap, setShowMap] = useState(true);
  const [expanded, setExpanded] = useState(new Set<string>());
  const expandedRef = useRef(expanded);
  expandedRef.current = expanded;
  const [expansionAnchor, setExpansionAnchor] = useState<{ id: string; x: number; y: number } | null>(null);
  const selectRef = useRef(onSelectStep);
  selectRef.current = onSelectStep;
  const selectStep = useCallback((step: GraphStep) => selectRef.current(step), []);
  const fullscreenButton = useRef<HTMLButtonElement>(null);
  const movedNodes = useRef(new Set<string>());
  const canvas = useRef<HTMLDivElement>(null);
  const [canvasSize, setCanvasSize] = useState({ width: 1200, height: 800 });
  const [measured, setMeasured] = useState({ collapsed: new Map<string, number>(), expanded: new Map<string, number>() });
  const [nodes, setNodes, onNodesChange] = useNodesState<Node<HarnessNodeData>>([]);
  const handleNodesChange = useCallback((changes: NodeChange<Node<HarnessNodeData>>[]) => {
    onNodesChange(changes);
    const dimensions = changes.filter(change => change.type === "dimensions" && change.dimensions);
    if (dimensions.length) setMeasured(previous => {
      const next = { ...previous };
      for (const change of dimensions) if (change.type === "dimensions" && change.dimensions) {
        const height = Math.ceil(change.dimensions.height);
        const kind = expandedRef.current.has(change.id) ? "expanded" : "collapsed";
        if (next[kind].get(change.id) !== height) {
          if (next[kind] === previous[kind]) next[kind] = new Map(previous[kind]);
          next[kind].set(change.id, height);
        }
      }
      return next.collapsed !== previous.collapsed || next.expanded !== previous.expanded ? next : previous;
    });
  }, [onNodesChange]);
  useEffect(() => {
    if (!canvas.current) return;
    const observer = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect;
      if (width > 0 && height > 0) setCanvasSize(previous => previous.width === Math.round(width) && previous.height === Math.round(height) ? previous : { width: Math.round(width), height: Math.round(height) });
    });
    observer.observe(canvas.current);
    return () => observer.disconnect();
  }, []);
  const currentNodes = useRef(nodes);
  currentNodes.current = nodes;
  const toggleExpanded = useCallback((id: string) => {
    const node = currentNodes.current.find(node => node.id === id);
    if (node) setExpansionAnchor({ id, ...node.position });
    setFollowing(false);
    setExpanded(previous => { const next = new Set(previous); if (next.has(id)) next.delete(id); else next.add(id); return next; });
  }, []);
  const topologyKey = JSON.stringify(steps.map(step => [step.id, parentIds(step)]));
  const topology = useMemo(() => (JSON.parse(topologyKey) as [string, string[]][]).map(([id, parentIds]) => ({ id, parentId: null, parentIds })), [topologyKey]);
  // Expansion must never compete for another global layout. Keep the compact
  // geometry separate from detail sizes, then make room around the clicked card.
  const basePositions = useMemo(() => layoutGraph(topology, canvasSize, measured.collapsed), [topology, canvasSize, measured.collapsed]);
  const positions = useMemo(() => {
    const heights = new Map(topology.map(step => [step.id, (expanded.has(step.id) ? measured.expanded.get(step.id) : undefined) || measured.collapsed.get(step.id) || 174]));
    return expandLayout(basePositions, heights, expansionAnchor);
  }, [topology, basePositions, measured, expanded, expansionAnchor]);
  const { layout, edges } = useMemo(() => {
    const layout: Node<HarnessNodeData>[] = [];
    const edges: Edge[] = [];
    const byId = new Map(steps.map(step => [step.id, step]));
    for (const step of steps) {
      const parents = parentIds(step);
      const { x, y } = positions.get(step.id)!;
      layout.push({ id: step.id, type: "harnessNode", position: { x, y }, data: { step, isSelected: selectedStep?.id === step.id, expanded: expanded.has(step.id), onToggle: toggleExpanded, onSelect: selectStep } });
      for (const parent of parents) if (byId.has(parent)) {
        const ports = edgePorts(positions.get(parent)!, positions.get(step.id)!);
        edges.push({ id: `${parent}->${step.id}`, source: parent, target: step.id, sourceHandle: `out-${ports.source}`, targetHandle: `in-${ports.target}`, type: "default", selectable: false, focusable: false, reconnectable: false, interactionWidth: 0, animated: active && step.status === "running", label: parents.length > 1 ? "汇合" : undefined, style: { stroke: step.status === "failed" ? "var(--red)" : step.status === "running" ? "var(--blue)" : "var(--border-hover)", strokeDasharray: "5 5" }, labelStyle: { fill: "var(--text-secondary)", fontSize: 13 }, labelBgStyle: { fill: "var(--bg-canvas)" } });
      }
    }
    return { layout, edges };
  }, [active, steps, selectedStep?.id, selectStep, toggleExpanded, expanded, positions]);
  useLayoutEffect(() => {
    setNodes(previous => reconcileNodes(previous, layout));
  }, [layout, setNodes]);
  // Streamed text/status updates must not restart a position animation.
  const positionKey = JSON.stringify(layout.map(node => [node.id, node.position.x, node.position.y]));
  useEffect(() => {
    const targets = new Map<string, Point>((JSON.parse(positionKey) as [string, number, number][]).map(([id, x, y]) => [id, { x, y }]));
    const motion = planNodeMotion(currentNodes.current, targets, movedNodes.current);
    if (!motion.size) return;
    const ms = motionDuration();
    if (!ms) { setNodes(previous => applyNodeMotion(previous, motion, 1, movedNodes.current)); return; }
    let frame = 0;
    const start = performance.now();
    const animate = (now: number) => {
      const progress = Math.min(1, (now - start) / ms);
      setNodes(previous => applyNodeMotion(previous, motion, progress, movedNodes.current));
      if (progress < 1) frame = requestAnimationFrame(animate);
    };
    frame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frame);
  }, [positionKey, setNodes]);
  useEffect(() => { if (fullscreen) fullscreenButton.current?.focus(); }, [fullscreen]);
  const running = steps.filter(step => step.status === "running" && (step.parentId || step.parentIds?.length)).slice(-2);
  const joined = steps.find(step => step.agentId === "coordinator" && step.status !== "pending" && step.status !== "running");
  const focus = running.length ? running : joined ? [joined] : steps.slice(-1);
  const focusKey = JSON.stringify(focus.map(step => step.id));
  useEffect(() => {
    if (!active || !following || !initialized) return;
    const ids = JSON.parse(focusKey) as string[];
    if (!ids.length) return;
    const timer = setTimeout(() => void fitView({ nodes: ids.map(id => ({ id })), padding: .4, minZoom: .7, maxZoom: 1, duration: motionDuration() }), motionDuration());
    return () => clearTimeout(timer);
  }, [active, initialized, focusKey, following, fullscreen, fitView]);
  const fit = () => { setFollowing(false); void fitView({ padding: .22, maxZoom: 1, duration: motionDuration() }); };
  return <div ref={canvas} className="workflow-canvas" aria-label="流程画板">
    <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodesChange={handleNodesChange} nodesConnectable={false} nodeDragThreshold={4} minZoom={.15} maxZoom={2} onNodeDragStart={(_event, node) => { movedNodes.current.add(node.id); setFollowing(false); }} onMoveStart={event => { if (event) setFollowing(false); }}>
      <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="var(--border-subtle)" />
      {steps.length > 4 && showMap && <MiniMap pannable zoomable nodeColor="var(--border-hover)" maskColor="color-mix(in srgb, var(--bg-canvas) 75%, transparent)" ariaLabel="流程概览" onClick={() => setFollowing(false)} />}
    </ReactFlow>
    <div className="canvas-toolbar">
      {!!steps.length && <button className="text-button" aria-pressed={following} onClick={() => setFollowing(!following)}><Focus size={16} />跟随流程</button>}
      {steps.length > 4 && <button className="icon-button" aria-label="流程概览" aria-pressed={showMap} onClick={() => setShowMap(!showMap)}><MapIcon size={17} /></button>}
      {onToggleFullscreen && <button ref={fullscreenButton} className="icon-button" aria-label={fullscreen ? "退出全屏画板" : "全屏画板"} title={fullscreen ? "退出全屏 · Esc" : "全屏画板"} onClick={onToggleFullscreen}>{fullscreen ? <Minimize2 size={18} /> : <Maximize2 size={18} />}</button>}
    </div>
    <div className="canvas-zoom" role="group" aria-label="画板缩放">
      <button className="icon-button" aria-label="放大画板" onClick={() => { setFollowing(false); void zoomIn({ duration: motionDuration() }); }}><Plus size={19} /></button>
      <button className="icon-button" aria-label="缩小画板" onClick={() => { setFollowing(false); void zoomOut({ duration: motionDuration() }); }}><Minus size={19} /></button>
      <button className="icon-button" aria-label="适应画板" onClick={fit}><Scan size={18} /></button>
    </div>
    {!steps.length && <div className="canvas-empty">Goal</div>}
  </div>;
}
export function CanvasGraph(props: CanvasGraphProps) { return <ReactFlowProvider><FlowInner {...props} /></ReactFlowProvider>; }
