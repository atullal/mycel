import { useMemo } from "react";
import qrcode from "qrcode-generator";

/** A QR code drawn as one SVG path in the current text colour. */
export function Qr({ value, size = 184, label }: { value: string; size?: number; label: string }) {
  const { d, n } = useMemo(() => {
    const qr = qrcode(0, "M");
    qr.addData(value);
    qr.make();
    const n = qr.getModuleCount();
    let d = "";
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (!qr.isDark(r, c)) continue;
        // Merge horizontal runs into one rect for a compact path.
        let run = 1;
        while (c + run < n && qr.isDark(r, c + run)) run++;
        d += `M${c} ${r}h${run}v1h-${run}z`;
        c += run - 1;
      }
    }
    return { d, n };
  }, [value]);

  const quiet = 2;
  return (
    <svg
      className="qr"
      width={size}
      height={size}
      viewBox={`${-quiet} ${-quiet} ${n + quiet * 2} ${n + quiet * 2}`}
      role="img"
      aria-label={label}
      shapeRendering="crispEdges"
    >
      <rect x={-quiet} y={-quiet} width={n + quiet * 2} height={n + quiet * 2} fill="var(--qr-bg, #fff)" />
      <path d={d} fill="var(--qr-fg, #000)" />
    </svg>
  );
}
