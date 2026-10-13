"use client";

interface AppLoaderProps {
  /** Emphasized line (e.g. host name); omitted when there is none. */
  title?: string;
  message: string;
  /** Smaller mark without the bar, for panels inside a view. */
  compact?: boolean;
}

// Full-screen wait state: app-mark tiles light in turn under a scan line.
export default function AppLoader({ title, message, compact = false }: AppLoaderProps) {
  return (
    <div role="status" aria-live="polite" className={compact ? "wa-loader wa-loader--compact" : "wa-loader"}>
      <div className="wa-loader__mark" aria-hidden="true">
        <span className="wa-loader__glow" />
        <svg viewBox="0 0 64 64">
          <rect className="wa-loader__tile" x="4" y="4" width="26" height="26" rx="3" />
          <rect className="wa-loader__tile" x="34" y="4" width="26" height="26" rx="3" />
          <rect className="wa-loader__tile" x="34" y="34" width="26" height="26" rx="3" />
          <rect className="wa-loader__tile" x="4" y="34" width="26" height="26" rx="3" />
        </svg>
        <span className="wa-loader__scan" />
      </div>
      <div className="wa-loader__text">
        {title && <strong className="wa-loader__title">{title}</strong>}
        <span className="wa-loader__message">
          {message}
          <span className="parse-progress__dots">...</span>
        </span>
      </div>
      {!compact && <div className="wa-loader__bar" aria-hidden="true"><span /></div>}
    </div>
  );
}
