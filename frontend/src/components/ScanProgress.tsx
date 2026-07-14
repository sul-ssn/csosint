"use client";

import { useEffect, useRef, useState } from "react";

import { wsBase } from "@/lib/api";
import type { ProgressEvent } from "@/lib/types";

// Живой прогресс скана через WS /ws/scan/{jobId} (ТЗ §7).
export default function ScanProgress({
  jobId,
  onDone,
}: {
  jobId: number;
  onDone: (ok: boolean) => void;
}) {
  const [events, setEvents] = useState<ProgressEvent[]>([]);
  const done = useRef(false);

  useEffect(() => {
    const ws = new WebSocket(`${wsBase()}/ws/scan/${jobId}`);
    ws.onmessage = (m) => {
      const ev = JSON.parse(m.data) as ProgressEvent;
      setEvents((prev) => [...prev, ev]);
      if ((ev.event === "done" || ev.event === "failed") && !done.current) {
        done.current = true;
        onDone(ev.event === "done");
        ws.close();
      }
    };
    ws.onerror = () => {
      if (!done.current) {
        done.current = true;
        onDone(false);
      }
    };
    return () => ws.close();
  }, [jobId, onDone]);

  function render(ev: ProgressEvent): string {
    if (ev.event === "source") return `source · ${ev.source} — ${ev.status}`;
    if (ev.counts) return `${ev.event} · ${JSON.stringify(ev.counts)}`;
    return `${ev.event}${ev.status ? ` · ${ev.status}` : ""}`;
  }

  return (
    <div className="panel">
      <strong>Прогресс сбора</strong>
      <ul className="progress" style={{ marginTop: 10 }}>
        {events.length === 0 && <li className="muted">ожидание событий…</li>}
        {events.map((ev, i) => (
          <li key={i}>{render(ev)}</li>
        ))}
      </ul>
    </div>
  );
}
