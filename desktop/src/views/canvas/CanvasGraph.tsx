import { useMemo, useEffect } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  Node,
  Edge,
  useReactFlow,
  ReactFlowProvider,
  BackgroundVariant,
} from "@xyflow/react";
import { HarnessNode, HarnessNodeData } from "./nodes/HarnessNode";
import { GraphStep } from "../../core";

interface CanvasGraphProps {
  steps: GraphStep[];
  selectedStep: GraphStep | null;
  onSelectStep: (step: GraphStep) => void;
}

const nodeTypes = {
  harnessNode: HarnessNode,
};

function FlowInner({ steps, selectedStep, onSelectStep }: CanvasGraphProps) {
  const { setCenter, fitView } = useReactFlow();

  const { nodes, edges } = useMemo(() => {
    const nodeList: Node[] = [];
    const edgeList: Edge[] = [];

    const X_GAP = 300;
    const Y_GAP = 130;

    let mainIndex = 0;
    const branchCounters: Record<string, number> = {};
    const stepPositions: Record<string, { x: number; y: number }> = {};

    steps.forEach((step) => {
      let x = 80;
      let y = 180;

      // Extract all parent IDs
      const parentIds: string[] = [];
      if (step.parentIds && step.parentIds.length > 0) {
        parentIds.push(...step.parentIds);
      } else if (step.parentId) {
        parentIds.push(step.parentId);
      }

      if (step.agentId === "main" && parentIds.length > 1) {
        // Multi-parent Join / Merge node back to main
        const maxX = Math.max(...parentIds.map((p) => stepPositions[p]?.x ?? 80));
        x = maxX + X_GAP;
        y = 180;
        mainIndex = Math.floor((x - 80) / X_GAP) + 1;
      } else if (step.agentId === "main" || parentIds.length === 0) {
        // Sequential main step
        x = 80 + mainIndex * X_GAP;
        y = 180;
        mainIndex++;
      } else {
        // Branching child step
        const firstParentId = parentIds[0];
        const parentPos = stepPositions[firstParentId]
          ? stepPositions[firstParentId]
          : { x: 80 + (mainIndex - 1) * X_GAP, y: 180 };

        const branchIdx = branchCounters[firstParentId] || 0;
        branchCounters[firstParentId] = branchIdx + 1;

        const offsetMap = [-1, 1, -2, 2];
        const slotOffset = offsetMap[branchIdx % offsetMap.length] ?? 1;

        x = parentPos.x + X_GAP;
        y = 180 + slotOffset * Y_GAP;
      }

      stepPositions[step.id] = { x, y };

      nodeList.push({
        id: step.id,
        type: "harnessNode",
        position: { x, y },
        data: {
          step,
          isSelected: selectedStep?.id === step.id,
          onSelect: onSelectStep,
        } as HarnessNodeData,
      });

      // Add edge for each parent
      parentIds.forEach((pId) => {
        if (stepPositions[pId]) {
          edgeList.push({
            id: `e-${pId}-${step.id}`,
            source: pId,
            target: step.id,
            animated: step.status === "running",
            style: {
              stroke: step.status === "running" ? "#a1a1aa" : "#3f3f46",
              strokeWidth: 1.5,
            },
          });
        }
      });
    });

    return { nodes: nodeList, edges: edgeList };
  }, [steps, selectedStep, onSelectStep]);

  useEffect(() => {
    if (steps.length === 0) return;
    const runningStep = steps.find((s) => s.status === "running") || steps[steps.length - 1];
    const targetNode = nodes.find((n) => n.id === runningStep?.id);

    if (targetNode) {
      setCenter(targetNode.position.x + 130, targetNode.position.y + 50, {
        duration: 600,
        zoom: 1.0,
      });
    } else {
      fitView({ padding: 0.25, duration: 500 });
    }
  }, [steps.length, setCenter, fitView, nodes]);

  return (
    <div className="w-full h-full relative">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        minZoom={0.2}
        maxZoom={2.0}
        panOnDrag={true}
        selectionOnDrag={false}
        panOnScroll={false}
        zoomOnScroll={true}
        nodesDraggable={true}
        elementsSelectable={true}
        proOptions={{ hideAttribution: true }}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={24}
          size={1.5}
          color="#52525b"
        />
        <Controls
          showInteractive={false}
          className="!m-4 !border-zinc-800 !bg-[#121215]"
        />
      </ReactFlow>
    </div>
  );
}

export function CanvasGraph(props: CanvasGraphProps) {
  return (
    <ReactFlowProvider>
      <FlowInner {...props} />
    </ReactFlowProvider>
  );
}
