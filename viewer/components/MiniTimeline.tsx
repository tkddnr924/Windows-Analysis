"use client";

export interface TimelinePoint {
  label: string;
  value: string;
}

export default function MiniTimeline({ points }: { points: TimelinePoint[] }) {
  const parsed = points
    .filter((p) => p.value)
    .map((p) => ({ ...p, date: new Date(p.value.replace(" ", "T")) }))
    .filter((p) => !Number.isNaN(p.date.getTime()));

  if (parsed.length < 2) return null;

  const sorted = [...parsed].sort((a, b) => a.date.getTime() - b.date.getTime());
  const min = sorted[0].date.getTime();
  const max = sorted[sorted.length - 1].date.getTime();
  const span = max - min || 1;

  return (
    <div style={{ padding: "12px 4px 22px" }}>
      <div style={{ position: "relative", height: 2, background: "var(--border)", borderRadius: 1, margin: "0 8px" }}>
        {sorted.map((p, i) => {
          const pct = ((p.date.getTime() - min) / span) * 100;
          const isEndpoint = i === 0 || i === sorted.length - 1;
          return (
            <div
              key={`${p.label}-${p.value}`}
              title={`${p.label}: ${p.value}`}
              style={{
                position: "absolute",
                left: `${pct}%`,
                top: "50%",
                transform: "translate(-50%, -50%)",
                width: isEndpoint ? 10 : 7,
                height: isEndpoint ? 10 : 7,
                borderRadius: "50%",
                background: "var(--accent)",
                opacity: isEndpoint ? 1 : 0.55,
                border: "2px solid var(--bg-panel)",
              }}
            />
          );
        })}
      </div>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          marginTop: 6,
          fontSize: 10,
          color: "var(--text-dim)",
          fontFamily: "var(--mono)",
        }}
      >
        <span>{sorted[0].label}: {sorted[0].value}</span>
        <span>{sorted[sorted.length - 1].label}: {sorted[sorted.length - 1].value}</span>
      </div>
    </div>
  );
}
