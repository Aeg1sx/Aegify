"use client";

import { useEffect, useId, useRef, useState } from "react";
import { bundledLanguages, codeToTokens, type BundledLanguage, type ThemedToken } from "shiki";
import { Check, Copy, FileCode2, WrapText } from "lucide-react";
import { codeLanguage } from "@/lib/code-evidence";

interface CodeHighlightProps {
  code: string;
  language?: string;
  filePath?: string;
  lineStart?: number | null;
  highlightStart?: number;
  highlightEnd?: number;
  selectedLine?: number;
  onLineSelect?: (line: number) => void;
  label?: string;
}

export function CodeHighlight({ code, language, filePath, lineStart = 1, highlightStart, highlightEnd, selectedLine, onLineSelect, label }: CodeHighlightProps) {
  const id = useId();
  const selectedRef = useRef<HTMLTableRowElement>(null);
  const [wrap, setWrap] = useState(false);
  const [copyState, setCopyState] = useState("");
  const [result, setResult] = useState<{ key: string; tokens: ThemedToken[][] } | null>(null);
  const lang = codeLanguage(language || filePath?.split(".").pop());
  const clipped = code.slice(0, 100_000);
  const displayCode = clipped.replace(/\r\n/g, "\n");
  const key = lang + "\0" + displayCode;
  const lines = displayCode.split("\n");
  useEffect(() => {
    let active = true;
    if (displayCode.length <= 50_000) {
      codeToTokens(displayCode, { lang: lang in bundledLanguages ? lang as BundledLanguage : "text", theme: "github-dark" })
        .then(({ tokens }) => { if (active) setResult({ key, tokens }); })
        .catch(() => { if (active) setResult({ key, tokens: [] }); });
    }
    return () => { active = false; };
  }, [displayCode, lang, key]);
  useEffect(() => {
    if (selectedLine) selectedRef.current?.scrollIntoView({ block: "nearest", behavior: "auto" });
  }, [selectedLine]);
  useEffect(() => {
    if (!copyState) return;
    const timer = setTimeout(() => setCopyState(""), 2200);
    return () => clearTimeout(timer);
  }, [copyState]);

  return (
    <figure className="code-frame min-w-0 overflow-hidden rounded-lg border border-[#303640] bg-[#11151c] text-[#d5dbe5]" aria-label={filePath || label || "Code snippet"}>
      <figcaption className="flex min-h-10 flex-wrap items-center gap-2 border-b border-white/10 bg-[#191e27] px-3 py-2 text-xs">
        <FileCode2 className="h-3.5 w-3.5 shrink-0 text-slate-400" />
        <span className="min-w-0 flex-1 break-all font-mono">{filePath || label || lang}</span>
        <button type="button" aria-label="Wrap code lines" aria-pressed={wrap} onClick={() => setWrap(!wrap)} className="rounded p-1 hover:bg-white/10"><WrapText className="h-4 w-4" /></button>
        <button type="button" className="flex items-center gap-1 rounded px-1.5 py-1 hover:bg-white/10" aria-label="Copy code" onClick={async () => {
          try { await navigator.clipboard.writeText(code); setCopyState("Copied"); }
          catch { setCopyState("Copy failed"); }
        }}>{copyState === "Copied" ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}<span aria-live="polite">{copyState || "Copy"}</span></button>
      </figcaption>
      {!code ? <p className="p-5 text-sm text-slate-400">No source snippet in this artifact.</p> : (
        <div className="code-scroll max-h-[480px] overflow-auto py-2" tabIndex={0} aria-label="Scrollable source code">
          <table className="w-full border-collapse font-mono text-[13px] leading-6"><tbody>
            {lines.map((line, index) => {
              const number = (lineStart ?? 1) + index;
              const marked = lineStart !== null && highlightStart !== undefined && number >= highlightStart && number <= (highlightEnd ?? highlightStart);
              const active = lineStart !== null && selectedLine === number;
              const tokens = result?.key === key ? result.tokens[index] : null;
              return <tr key={index} id={id + "-L" + number} ref={active ? selectedRef : undefined} data-source-line={lineStart === null ? undefined : number} data-highlighted={marked || undefined} className={active ? "bg-blue-400/15" : marked ? "bg-red-400/10" : "hover:bg-white/[.03]"}>
                <td className={"w-12 select-none border-l-2 pr-3 pl-2 text-right align-top " + (marked ? "border-red-400 text-red-300" : "border-transparent text-slate-500")}>
                  {onLineSelect && lineStart !== null ? <button type="button" className="w-full hover:text-white" aria-label={"Select source line " + number} onClick={() => onLineSelect(number)}>{number}</button> : number}
                </td>
                <td className={"pr-4 " + (wrap ? "whitespace-pre-wrap break-all" : "whitespace-pre")}>
                  {tokens?.length ? tokens.map((token, i) => <span key={i} style={{ color: token.color, fontStyle: (token.fontStyle ?? 0) & 1 ? "italic" : undefined, fontWeight: (token.fontStyle ?? 0) & 2 ? "bold" : undefined }}>{token.content}</span>) : line || " "}
                </td>
              </tr>;
            })}
          </tbody></table>
        </div>
      )}
      <div className="flex flex-wrap gap-x-4 gap-y-1 border-t border-white/10 px-3 py-2 text-[11px] text-slate-400">
        <span>{lineStart === null ? "Relative lines · source offset unavailable" : "L" + lineStart + "–" + (lineStart + lines.length - 1)}</span>
        {highlightStart !== undefined && lineStart !== null && <span className="text-red-300">▎ Reported location · not a runtime verdict</span>}
        {code.length > clipped.length && <span>Preview limited to 100,000 characters · copy includes the full snippet</span>}
      </div>
    </figure>
  );
}

export function YamlHighlight({ code }: { code: string }) {
  return <CodeHighlight code={code} language="yaml" label="Rule definition" />;
}
