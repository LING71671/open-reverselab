import { useMemo, useEffect, useRef, useState } from "react";
import { ReactFlow, Background, Controls, useReactFlow, ReactFlowProvider, BackgroundVariant, useNodesState, type Node, type Edge } from "@xyflow/react";
import { Focus, Scan } from "lucide-react";
import { HarnessNode, type HarnessNodeData } from "./nodes/HarnessNode";
import type { GraphStep } from "../../core";
interface CanvasGraphProps { active: boolean; steps: GraphStep[]; selectedStep: GraphStep | null; onSelectStep: (step: GraphStep) => void }
const nodeTypes = { harnessNode: HarnessNode };
function FlowInner({ active, steps, selectedStep, onSelectStep }: CanvasGraphProps) {
  const { fitView } = useReactFlow();
  const [following, setFollowing] = useState(true);
  const movedNodes = useRef(new Set<string>());
  const [nodes, setNodes, onNodesChange] = useNodesState<Node<HarnessNodeData>>([]);
  const { layout, edges } = useMemo(() => {
    const positions = new Map<string, { x: number; y: number }>();
    const occupied = new Map<number, number[]>();
    const layout: Node<HarnessNodeData>[] = [];
    const edges: Edge[] = [];
    const byId = new Map(steps.map(step => [step.id, step]));
    const ordered: GraphStep[] = [];
    const visited = new Set<string>();
    const visit = (step: GraphStep) => {
      if (visited.has(step.id)) return;
      visited.add(step.id);
      for (const id of step.parentIds?.length ? step.parentIds : step.parentId ? [step.parentId] : []) {
        const parent = byId.get(id);
        if (parent) visit(parent);
      }
      ordered.push(step);
    };
    steps.forEach(visit);
    for (const step of ordered) {
      const parents = step.parentIds?.length ? step.parentIds : step.parentId ? [step.parentId] : [];
      const parentPositions = parents.map(id => positions.get(id)).filter((p): p is { x: number; y: number } => !!p);
      const x = parentPositions.length ? Math.max(...parentPositions.map(p => p.x)) + 330 : 0;
      let y = parentPositions.length ? parentPositions.reduce((sum, p) => sum + p.y, 0) / parentPositions.length : 0;
      const lanes = occupied.get(x) || [];
      while (lanes.some(lane => Math.abs(lane - y) < 155)) y += 170;
      occupied.set(x, [...lanes, y]); positions.set(step.id, { x, y });
      layout.push({ id: step.id, type: "harnessNode", position: { x, y }, data: { step, isSelected: selectedStep?.id === step.id, onSelect: onSelectStep } });
      for (const parent of parents) if (steps.some(s => s.id === parent)) edges.push({ id: `${parent}->${step.id}`, source: parent, target: step.id, animated: step.status === "running" });
    }
    return { layout, edges };
  }, [steps, selectedStep, onSelectStep]);
  useEffect(() => { setNodes(previous => layout.map(node => ({ ...node, position: movedNodes.current.has(node.id) ? previous.find(p => p.id === node.id)?.position || node.position : node.position }))); }, [layout, setNodes]);
  const duration = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches ? 0 : 250;
  useEffect(() => {
    if (!active || !following || !steps.length) return;
    const running = steps.filter(step => step.status === "running" && (step.parentId || step.parentIds?.length)).slice(-2);
    const joined = steps.find(step => step.agentId === "coordinator" && step.status !== "pending" && step.status !== "running");
    const focus = running.length ? running : joined ? [joined] : steps.slice(-1);
    const timer = setTimeout(() => void fitView({ nodes: focus.map(step => ({ id: step.id })), padding: .35, minZoom: .65, maxZoom: 1, duration: duration() }), 80);
    return () => clearTimeout(timer);
  }, [active, steps, following, fitView]);
  return <div className="w-full h-full relative">
    <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} onNodesChange={onNodesChange} fitView minZoom={.15} maxZoom={2} onNodeDragStart={(_event, node) => { movedNodes.current.add(node.id); setFollowing(false); }} onMoveStart={event => { if (event) setFollowing(false); }}>
      <Background variant={BackgroundVariant.Dots} gap={24} size={1} color="var(--border-subtle)" />
      <Controls showInteractive={false} />
    </ReactFlow>
    {!!steps.length && <div className="canvas-toolbar"><button className="text-button" aria-pressed={following} onClick={() => setFollowing(!following)}><Focus size={14} />跟随流程</button><button className="icon-button" aria-label="适应画板" title="适应画板" onClick={() => void fitView({ padding: .22, maxZoom: 1, duration: duration() })}><Scan size={15} /></button></div>}
    {!steps.length && <div className="canvas-empty">Goal</div>}
  </div>;
}
export function CanvasGraph(props: CanvasGraphProps) { return <ReactFlowProvider><FlowInner {...props} /></ReactFlowProvider>; }
