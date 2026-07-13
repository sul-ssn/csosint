"use client";

import cytoscape from "cytoscape";
import { useEffect, useRef } from "react";

import type { Graph } from "@/lib/types";

// Цвета по типу узла (domain/ip/service/cve).
const NODE_COLORS: Record<string, string> = {
  domain: "#4f8cff",
  ip: "#22c55e",
  service: "#f59e0b",
  cve: "#ef4444",
};

export default function GraphView({ graph }: { graph: Graph }) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!ref.current) return;
    const cy = cytoscape({
      container: ref.current,
      elements: [...graph.nodes, ...graph.edges],
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "font-size": 9,
            color: "#cdd7e6",
            "text-valign": "bottom",
            "text-margin-y": 3,
            "background-color": "#8892a6",
            width: 18,
            height: 18,
          },
        },
        ...Object.entries(NODE_COLORS).map(([type, color]) => ({
          selector: `node[type="${type}"]`,
          style: { "background-color": color },
        })),
        {
          selector: "edge",
          style: {
            width: 1,
            "line-color": "#38466a",
            "target-arrow-color": "#38466a",
            "target-arrow-shape": "triangle",
            "arrow-scale": 0.8,
            "curve-style": "bezier",
          },
        },
      ],
      layout: { name: "cose", animate: false, padding: 20 },
    });
    return () => cy.destroy();
  }, [graph]);

  const legend = Object.entries(NODE_COLORS);
  return (
    <div className="panel">
      <strong>Граф связей</strong>
      <div style={{ display: "flex", gap: 14, margin: "8px 0 12px", fontSize: 12 }}>
        {legend.map(([type, color]) => (
          <span key={type}>
            <span
              style={{
                display: "inline-block",
                width: 10,
                height: 10,
                borderRadius: 999,
                background: color,
                marginRight: 5,
              }}
            />
            {type}
          </span>
        ))}
      </div>
      <div ref={ref} style={{ width: "100%", height: 520, background: "#0b0f19", borderRadius: 8 }} />
    </div>
  );
}
