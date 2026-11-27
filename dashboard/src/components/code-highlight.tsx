"use client";

import { Fragment, useEffect, useId, useRef, useState, type CSSProperties } from "react";
import { bundledLanguages, codeToTokens, type BundledLanguage, type ThemedToken } from "shiki";
import { Check, Copy, FileCode2, WrapText } from "lucide-react";
import { codeLanguage, codePreview, lineRange } from "@/lib/code-evidence";

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
  const { text: displayCode, lines, truncated } = codePreview(code);
  const key = lang + "\0" + displayCode;
  const reported = highlightStart === undefined ? "" : lineRange(highlightStart, highlightEnd);
  useEffect(() => {
    let active = true;
    if (displayCode.length <= 50_000) {
      codeToTokens(displayCode, { lang: lang in bundledLanguages ? lang as BundledLanguage : "text",
        themes: { light: "github-light-high-contrast", dark: "github-dark-high-contrast" }, defaultColor: false })
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
    <figure className="code-frame min-w-0 overflow-hidden border-y border-border bg-card text-foreground" aria-label={filePath || label || "Code snippet"}>
      <figcaption className="flex min-h-11 items-center gap-1 border-b border-border bg-muted/60 px-3 text-xs">
        <FileCode2 aria-hidden className="mr-1 size-3.5 shrink-0 text-muted-foreground" />
        <span className="min-w-0 flex-1 py-2 font-mono [overflow-wrap:anywhere]">
          {filePath ? filePath.split(/(?<=[\\/])/).map((part, index) => <Fragment key={index}>{index > 0 && <wbr />}{part}</Fragment>) : label || lang}{reported && <>:{reported}</>}
        </span>
        {code && <><button type="button" aria-label="Wrap code lines" title="Wrap code lines" aria-pressed={wrap} onClick={() => setWrap(!wrap)} className="grid size-11 shrink-0 place-items-center rounded hover:bg-accent aria-pressed:bg-accent"><WrapText aria-hidden className="size-4" /></button>
        <button type="button" className="flex min-h-11 min-w-11 items-center justify-center gap-1 rounded px-2 hover:bg-accent" aria-label="Copy code" title="Copy code" onClick={async () => {
          try { await navigator.clipboard.writeText(code); setCopyState("Copied"); }
          catch { setCopyState("Copy failed"); }
        }}>{copyState === "Copied" ? <Check aria-hidden className="size-3.5" /> : <Copy aria-hidden className="size-3.5" />}<span className={copyState ? "" : "sr-only sm:not-sr-only"} aria-live="polite">{copyState || "Copy"}</span></button></>}
      </figcaption>
      {!code ? <p className="p-5 text-sm text-muted-foreground">No source snippet in this artifact.</p> : (
        <div className="code-scroll max-h-[480px] overflow-auto py-2" tabIndex={0} aria-label="Scrollable source code">
          <table className="w-full border-collapse font-mono text-[13px] leading-6"><tbody>
            {lines.map((line, index) => {
              const number = (lineStart ?? 1) + index;
              const marked = lineStart !== null && highlightStart !== undefined && number >= highlightStart && number <= (highlightEnd ?? highlightStart);
              const active = lineStart !== null && selectedLine === number;
              const tokens = result?.key === key ? result.tokens[index] : null;
              return <tr key={index} id={id + "-L" + number} ref={active ? selectedRef : undefined} data-source-line={lineStart === null ? undefined : number} data-highlighted={marked || undefined} data-selected={active || undefined}>
                <td aria-label={marked && !onLineSelect ? "Reported line " + number : undefined} className={"w-12 min-w-12 select-none whitespace-nowrap border-l-2 pr-3 pl-2 text-right align-top " + (marked || active ? "border-primary font-semibold text-primary" : "border-transparent text-muted-foreground")}>
                  {onLineSelect && lineStart !== null ? <button type="button" className="w-full hover:text-primary hover:underline" aria-label={"Select source line " + number} aria-description={marked ? "Reported location" : undefined} aria-current={active ? "location" : undefined} onClick={() => onLineSelect(number)}>{number}</button> : number}
                </td>
                <td className={"pr-4 " + (wrap ? "whitespace-pre-wrap break-all" : "whitespace-pre")}>
                  {tokens?.length ? tokens.map((token, i) => <span key={i} className="code-token" style={token.htmlStyle as CSSProperties}>{token.content}</span>) : line || " "}
                </td>
              </tr>;
            })}
          </tbody></table>
        </div>
      )}
      {code && <div className="flex flex-wrap gap-x-4 gap-y-1 border-t border-border px-3 py-2 text-xs text-muted-foreground">
        <span>{lineStart === null ? "Relative line numbers" : "Excerpt · L" + lineRange(lineStart, lineStart + lines.length - 1)}</span>
        {truncated && <span>Preview limited to 100,000 characters · copy includes the full snippet</span>}
      </div>}
    </figure>
  );
}

export function YamlHighlight({ code, filePath }: { code: string; filePath?: string }) {
  return <CodeHighlight code={code} language="yaml" filePath={filePath} label="YAML" />;
}
