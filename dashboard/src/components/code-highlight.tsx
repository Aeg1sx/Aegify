"use client";

import { useEffect, useState } from "react";
import { codeToHtml } from "shiki";

interface CodeHighlightProps {
  code: string;
  language?: string;
  lineStart?: number;
}

const EXT_MAP: Record<string, string> = {
      py: "python",
      js: "javascript",
      ts: "typescript",
      tsx: "tsx",
      jsx: "jsx",
      java: "java",
      go: "go",
      rs: "rust",
      rb: "ruby",
      php: "php",
      swift: "swift",
      kt: "kotlin",
      cs: "csharp",
      cpp: "cpp",
      c: "c",
      yml: "yaml",
      yaml: "yaml",
      sql: "sql",
      sh: "bash",
  bash: "bash",
};

function detectLanguage(code: string, filePath?: string): string {
  if (filePath) {
    const ext = filePath.split(".").pop()?.toLowerCase();
    if (ext && EXT_MAP[ext]) return EXT_MAP[ext];
  }

  // Heuristic detection
  if (/\bdef\s+\w+|import\s+\w+|from\s+\w+\s+import\b/.test(code)) return "python";
  if (/\bfunction\s+\w+|const\s+\w+|=>\s*{/.test(code)) return "javascript";
  if (/\bpublic\s+(class|static|void)\b/.test(code)) return "java";
  if (/\bfunc\s+\w+|package\s+\w+/.test(code)) return "go";

  return "python"; // default for SAST tool
}

export function CodeHighlight({
  code,
  language,
  lineStart = 1,
}: CodeHighlightProps) {
  const highlightKey = `${language || "auto"}\u0000${code}`;
  const [highlight, setHighlight] = useState<{
    key: string;
    html: string;
  } | null>(null);

  useEffect(() => {
    if (!code) return;
    let cancelled = false;

    // language prop might be a file extension like "py" or a language name like "python"
    const lang = language
      ? EXT_MAP[language.toLowerCase()] || language
      : detectLanguage(code);

    codeToHtml(code, {
      lang,
      theme: "github-dark",
    })
      .then((result) => {
        if (!cancelled) setHighlight({ key: highlightKey, html: result });
      })
      .catch(() => {
        // Fallback: plain text
        if (!cancelled) setHighlight({ key: highlightKey, html: "" });
      });
    return () => {
      cancelled = true;
    };
  }, [code, language, highlightKey]);

  if (!code) {
    return (
      <p className="text-xs text-muted-foreground italic">
        No code snippet available
      </p>
    );
  }

  if (!highlight || highlight.key !== highlightKey) {
    return (
      <div className="bg-[#0d1117] rounded-md p-4 animate-pulse">
        <div className="h-4 bg-gray-700 rounded w-3/4 mb-2" />
        <div className="h-4 bg-gray-700 rounded w-1/2" />
      </div>
    );
  }

  if (!highlight.html) {
    // Fallback to plain rendering with line numbers
    const lines = code.split("\n");
    return (
      <div className="bg-[#0d1117] rounded-md overflow-x-auto">
        <table className="w-full text-xs font-mono">
          <tbody>
            {lines.map((line, i) => (
              <tr key={i} className="hover:bg-white/5">
                <td className="px-3 py-0.5 text-right text-gray-500 select-none w-10 align-top">
                  {lineStart + i}
                </td>
                <td className="px-3 py-0.5 text-[#c9d1d9] whitespace-pre">
                  {line}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  // Add line numbers to shiki output
  const lines = code.split("\n");
  return (
    <div className="relative bg-[#0d1117] rounded-md overflow-x-auto">
      <div className="flex">
        <div className="flex-shrink-0 select-none text-right pr-2 pt-4 pb-4 pl-3">
          {lines.map((_, i) => (
            <div
              key={i}
              className="text-xs font-mono text-gray-500 leading-[1.45rem]"
            >
              {lineStart + i}
            </div>
          ))}
        </div>
        <div
          className="flex-1 overflow-x-auto [&>pre]:!bg-transparent [&>pre]:!m-0 [&>pre]:!p-4 [&>pre>code]:!text-xs [&>pre>code>.line]:leading-[1.45rem]"
          dangerouslySetInnerHTML={{ __html: highlight.html }}
        />
      </div>
    </div>
  );
}

export function YamlHighlight({ code }: { code: string }) {
  const [html, setHtml] = useState<string>("");

  useEffect(() => {
    if (!code) return;
    codeToHtml(code, {
      lang: "yaml",
      theme: "github-dark",
    })
      .then(setHtml)
      .catch(() => setHtml(""));
  }, [code]);

  if (!code) return null;

  if (!html) {
    return (
      <pre className="bg-[#0d1117] text-[#c9d1d9] font-mono text-xs p-4 rounded-md overflow-x-auto whitespace-pre-wrap max-h-96 overflow-y-auto">
        {code}
      </pre>
    );
  }

  return (
    <div
      className="max-h-96 overflow-y-auto overflow-x-auto rounded-md [&>pre]:!text-xs [&>pre]:!rounded-md [&>pre>code>.line]:leading-[1.45rem]"
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}
