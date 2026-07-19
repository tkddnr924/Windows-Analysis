"use client";

export interface OpenTab {
  key: string;
  label: string;
}

interface TabBarProps {
  tabs: OpenTab[];
  activeKey: string | null;
  onActivate: (key: string) => void;
  onClose: (key: string) => void;
}

export default function TabBar({ tabs, activeKey, onActivate, onClose }: TabBarProps) {
  if (tabs.length === 0) return null;

  return (
    <div
      style={{
        display: "flex",
        overflowX: "auto",
        background: "var(--bg-panel)",
        borderBottom: "1px solid var(--border)",
        flexShrink: 0,
      }}
    >
      {tabs.map(({ key, label }) => {
        const isActive = key === activeKey;
        return (
          <div
            key={key}
            onClick={() => onActivate(key)}
            title={label}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              padding: "8px 10px 8px 14px",
              cursor: "pointer",
              whiteSpace: "nowrap",
              flexShrink: 0,
              borderRight: "1px solid var(--border-subtle)",
              background: isActive ? "var(--bg)" : "transparent",
              borderTop: isActive ? "2px solid var(--accent)" : "2px solid transparent",
              color: isActive ? "var(--text)" : "var(--text-dim)",
              fontSize: 12.5,
              fontWeight: isActive ? 600 : 400,
            }}
            onMouseEnter={(e) => {
              if (!isActive) e.currentTarget.style.background = "var(--bg-hover)";
            }}
            onMouseLeave={(e) => {
              if (!isActive) e.currentTarget.style.background = "transparent";
            }}
          >
            <span>{label}</span>
            <span
              onClick={(e) => {
                e.stopPropagation();
                onClose(key);
              }}
              style={{
                color: "var(--text-faint)",
                fontSize: 14,
                lineHeight: 1,
                padding: "1px 4px",
                borderRadius: "var(--radius-sm)",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = "var(--bg-hover)";
                e.currentTarget.style.color = "var(--text)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "transparent";
                e.currentTarget.style.color = "var(--text-faint)";
              }}
            >
              ×
            </span>
          </div>
        );
      })}
    </div>
  );
}
