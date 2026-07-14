"use client";

import cytoscape from "cytoscape";
import fcose from "cytoscape-fcose";
import { useEffect, useMemo, useRef, useState } from "react";

import type { Graph, GraphNode } from "@/lib/types";

// fcose регистрируем один раз (защита от повторной регистрации при HMR).
type Reg = typeof cytoscape & { __fcose?: boolean };
if (!(cytoscape as Reg).__fcose) {
  cytoscape.use(fcose);
  (cytoscape as Reg).__fcose = true;
}

// Типы узлов (валидированная палитра). CVE окрашивается по severity.
const TYPE: Record<string, { color: string; label: string }> = {
  domain: { color: "#6897f5", label: "Домен" },
  ip: { color: "#55b895", label: "IP-адрес" },
  service: { color: "#d7a35c", label: "Сервис" },
  cve: { color: "#dc6868", label: "Уязвимость" },
  country: { color: "#8491a8", label: "Страна" },
  org: { color: "#a889cf", label: "Организация" },
};
const ORDER = ["domain", "ip", "service", "cve", "org", "country"];
const SEV: Record<string, string> = {
  CRITICAL: "#d03b3b",
  HIGH: "#ec835a",
  MEDIUM: "#fab219",
  LOW: "#8892a6",
  UNKNOWN: "#8892a6",
};

const LAYOUT = {
  name: "fcose",
  quality: "default",
  animate: false,
  randomize: true,
  nodeSeparation: 120,
  idealEdgeLength: 150,
  nodeRepulsion: 12000,
  gravity: 0.12,
  gravityRange: 4,
  numIter: 3500,
  padding: 90,
} as unknown as cytoscape.LayoutOptions;

export default function GraphView({ graph }: { graph: Graph }) {
  const ref = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const queryRef = useRef("");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<GraphNode["data"] | null>(null);
  const [hiddenTypes, setHiddenTypes] = useState<Set<string>>(new Set());

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const n of graph.nodes) {
      const t = n.data.type as string;
      c[t] = (c[t] ?? 0) + 1;
    }
    return c;
  }, [graph]);

  useEffect(() => {
    if (!ref.current) return;
    const cy = cytoscape({
      container: ref.current,
      elements: [...graph.nodes, ...graph.edges],
      minZoom: 0.2,
      maxZoom: 3,
      style: [
        {
          selector: "node",
          style: {
            label: "data(label)",
            "font-size": 10,
            "font-weight": 500,
            color: "#dbe5f3",
            "text-halign": "right",
            "text-valign": "center",
            "text-margin-x": 7,
            "text-wrap": "none",
            "text-outline-color": "#080c1c",
            "text-outline-width": 2,
            "min-zoomed-font-size": 7,
            "background-color": "#8491a8",
            "border-width": 1,
            "border-color": "rgba(255,255,255,.7)",
            shape: "ellipse",
            width: 13,
            height: 13,
          },
        },
        { selector: 'node[type="domain"]', style: { "background-color": TYPE.domain.color, width: 14, height: 14 } },
        { selector: 'node[type="ip"]', style: { "background-color": TYPE.ip.color, width: 19, height: 19, "font-size": 11, "font-weight": 700 } },
        { selector: 'node[type="service"]', style: { "background-color": TYPE.service.color, width: 13, height: 13 } },
        { selector: 'node[type="country"]', style: { "background-color": TYPE.country.color, width: 11, height: 11 } },
        { selector: 'node[type="org"]', style: { "background-color": TYPE.org.color, width: 15, height: 15 } },
        { selector: 'node[type="cve"]', style: { "background-color": SEV.UNKNOWN, width: 15, height: 15 } },
        { selector: 'node[type="cve"][severity="CRITICAL"]', style: { "background-color": SEV.CRITICAL, width: 21, height: 21, "border-width": 2 } },
        { selector: 'node[type="cve"][severity="HIGH"]', style: { "background-color": SEV.HIGH, width: 18, height: 18 } },
        { selector: 'node[type="cve"][severity="MEDIUM"]', style: { "background-color": SEV.MEDIUM, width: 16, height: 16 } },
        { selector: 'node[type="cve"][severity="LOW"]', style: { "background-color": SEV.LOW } },
        {
          selector: "edge",
          style: {
            width: 1,
            "line-color": "#65708c",
            "target-arrow-shape": "none",
            "curve-style": "straight",
            opacity: 0.42,
          },
        },
        { selector: 'edge[type="resolves"]', style: { "line-color": "#617caf" } },
        { selector: 'edge[type="runs"]', style: { "line-color": "#658879" } },
        { selector: 'edge[type="vulnerable"]', style: { "line-color": "#9d626a", width: 1.25, opacity: .58 } },
        { selector: 'edge[type="geo"]', style: { "line-color": "#586174", "line-style": "dashed" } },
        { selector: 'edge[type="hosted"]', style: { "line-color": "#715f85", "line-style": "dashed" } },
        { selector: ".dim", style: { opacity: 0.08 } },
        { selector: "node.hot", style: { "border-color": "#eaf1fb", "border-width": 3 } },
        { selector: "node.match", style: { "border-color": "#eaf1fb", "border-width": 3 } },
        { selector: "node.selected", style: { "border-color": "#ffffff", "border-width": 3, "overlay-color": "#8db3ff", "overlay-opacity": 0.16, "overlay-padding": 9 } },
        { selector: "edge.hot", style: { opacity: 1, width: 2.8, "arrow-scale": 1 } },
      ],
      layout: LAYOUT,
    });
    cyRef.current = cy;

    cy.on("tap", "node", (e) => {
      cy.nodes().removeClass("selected");
      e.target.addClass("selected");
      setSelected({ ...e.target.data() } as GraphNode["data"]);
    });
    cy.on("tap", (e) => {
      if (e.target === cy) {
        cy.nodes().removeClass("selected");
        setSelected(null);
      }
    });

    cy.on("mouseover", "node", (e) => {
      if (queryRef.current) return;
      const nb = e.target.closedNeighborhood();
      cy.elements().difference(nb).addClass("dim");
      nb.removeClass("dim").addClass("hot");
    });
    cy.on("mouseout", "node", () => {
      if (queryRef.current) return;
      cy.elements().removeClass("dim hot");
    });

    return () => cy.destroy();
  }, [graph]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().style("display", "element");
      for (const type of hiddenTypes) cy.nodes(`[type = "${type}"]`).style("display", "none");
      cy.edges().forEach((edge) => {
        if (edge.source().style("display") === "none" || edge.target().style("display") === "none") edge.style("display", "none");
      });
    });
    cy.fit(cy.elements(":visible"), 50);
  }, [hiddenTypes]);

  // Поиск: подсветить совпадения по подписи, приглушить остальное.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().removeClass("dim match hot");
      const q = query.trim().toLowerCase();
      if (!q) return;
      const hit = cy.nodes().filter((n) => String(n.data("label")).toLowerCase().includes(q));
      cy.elements().addClass("dim");
      hit.removeClass("dim").addClass("match");
    });
  }, [query]);

  const total = graph.nodes.length;

  function toggleType(type: string) {
    setHiddenTypes((current) => {
      const next = new Set(current);
      if (next.has(type)) next.delete(type); else next.add(type);
      return next;
    });
  }

  const selectedEdges = selected
    ? graph.edges.filter((e) => e.data.source === selected.id || e.data.target === selected.id).length
    : 0;

  return (
    <div className="graph-full">
      <div className="graph-toolbar">
        <div><span className="live-dot" />{total} узлов · {graph.edges.length} связей</div>
        <div className="graph-actions">
          <button type="button" aria-label="Уменьшить" onClick={() => cyRef.current?.zoom({ level: Math.max(.2, (cyRef.current?.zoom() ?? 1) - .2), renderedPosition: { x: 400, y: 300 } })}>−</button>
          <button type="button" aria-label="Увеличить" onClick={() => cyRef.current?.zoom({ level: Math.min(3, (cyRef.current?.zoom() ?? 1) + .2), renderedPosition: { x: 400, y: 300 } })}>+</button>
          <button type="button" onClick={() => cyRef.current?.fit(undefined, 50)}>По размеру</button>
          <button type="button" onClick={() => cyRef.current?.layout(LAYOUT).run()}>Перестроить</button>
        </div>
      </div>
      <div className="graph-shell">
        <div ref={ref} className="graph-cy" />
        <aside className="graph-side">
          <input
            className="side-search"
            placeholder="Поиск узла…"
            value={query}
            onChange={(e) => {
              queryRef.current = e.target.value;
              setQuery(e.target.value);
            }}
          />
          <div className="side-title">Показывать на карте</div>
          <div className="side-legend">
            {ORDER.filter((t) => counts[t]).map((t) => (
              <button type="button" className={`legend-row legend-toggle ${hiddenTypes.has(t) ? "off" : ""}`} key={t} onClick={() => toggleType(t)}>
                <span
                  className="lg-dot"
                  style={{ background: TYPE[t].color, borderRadius: t === "cve" ? 2 : 999 }}
                />
                <span>{TYPE[t].label}</span>
                <b>{counts[t]}</b>
              </button>
            ))}
            {counts.cve ? (
              <div className="sev-legend">
                severity:
                {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => (
                  <span key={s} className="lg-dot sq" style={{ background: SEV[s] }} title={s} />
                ))}
              </div>
            ) : null}
          </div>

          <div className="side-title">Выбранный объект</div>
          {selected ? <div className="node-inspector">
            <span className="node-type"><i style={{ background: TYPE[String(selected.type)]?.color }} />{TYPE[String(selected.type)]?.label ?? selected.type}</span>
            <b>{String(selected.label)}</b>
            <dl>
              {Object.entries(selected).filter(([key, value]) => !["id", "label", "type"].includes(key) && value != null).map(([key, value]) => <div key={key}><dt>{key.replaceAll("_", " ")}</dt><dd>{String(value)}</dd></div>)}
              <div><dt>связей</dt><dd>{selectedEdges}</dd></div>
            </dl>
          </div> : <div className="inspector-empty">Нажмите на узел, чтобы изучить объект и его связи.</div>}
          <p className="graph-tip">Наведите на узел, чтобы подсветить ближайшее окружение. Размер CVE отражает уровень severity.</p>
        </aside>
      </div>
    </div>
  );
}
