export interface ReviewLine {
  kind: "context" | "remove" | "add";
  original: number | null;
  proposed: number | null;
  text: string;
}

/** Align two saved excerpts. Indices are relative to their respective excerpts. */
export function remediationDiff(original: string, proposed: string): ReviewLine[] | null {
  if (original.length > 40_000 || proposed.length > 40_000) return null;
  const lines = (text: string) => text ? text.replace(/\r\n/g, "\n").split("\n") : [];
  const a = lines(original), b = lines(proposed);
  if (a.length + b.length > 800 || a.length * b.length > 100_000) return null;
  const width = b.length + 1;
  const lengths = new Uint16Array((a.length + 1) * width);
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      const cell = i * width + j;
      lengths[cell] = a[i] === b[j] ? lengths[cell + width + 1] + 1
        : Math.max(lengths[cell + width], lengths[cell + 1]);
    }
  }
  const rows: ReviewLine[] = [];
  let i = 0, j = 0;
  while (i < a.length || j < b.length) {
    const cell = i * width + j;
    if (i < a.length && j < b.length && a[i] === b[j]) {
      rows.push({ kind: "context", original: i + 1, proposed: j + 1, text: a[i] });
      i++; j++;
    } else if (i < a.length && (j === b.length || lengths[cell + width] >= lengths[cell + 1])) {
      rows.push({ kind: "remove", original: i + 1, proposed: null, text: a[i++] });
    } else {
      rows.push({ kind: "add", original: null, proposed: j + 1, text: b[j++] });
    }
  }
  return rows;
}
