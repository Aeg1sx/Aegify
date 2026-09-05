"use client";

import ReactMarkdown from "react-markdown";
import { isValidElement, type ReactNode } from "react";
import remarkGfm from "remark-gfm";
import { CodeHighlight } from "@/components/code-highlight";

interface MarkdownProps {
  content: string;
}

export function Markdown({ content }: MarkdownProps) {
  return (
    <div className="prose prose-sm prose-invert max-w-none">
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        pre({ children }) {
          if (isValidElement<{ className?: string; children?: ReactNode }>(children)) {
            const language = /language-([^\s]+)/.exec(children.props.className || "")?.[1];
            return <CodeHighlight code={String(children.props.children ?? "").replace(/\n$/, "")} language={language || "text"} label="Code / suggested change" />;
          }
          return <pre className="overflow-auto">{children}</pre>;
        },
        code({ children }) {
          return <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-sm">{children}</code>;
        },
        table({ children }) {
          return <div className="overflow-x-auto"><table className="data-table">{children}</table></div>;
        },
        p({ children }) {
          return <p className="mb-3 last:mb-0 leading-relaxed">{children}</p>;
        },
        ul({ children }) {
          return <ul className="list-disc pl-5 mb-3 space-y-1">{children}</ul>;
        },
        ol({ children }) {
          return <ol className="list-decimal pl-5 mb-3 space-y-1">{children}</ol>;
        },
        li({ children }) {
          return <li className="text-sm">{children}</li>;
        },
        strong({ children }) {
          return <strong className="font-semibold text-foreground">{children}</strong>;
        },
        h4({ children }) {
          return <h4 className="text-sm font-semibold mt-4 mb-2">{children}</h4>;
        },
        h3({ children }) {
          return <h3 className="text-base font-semibold mt-4 mb-2">{children}</h3>;
        },
        a({ href, children }) {
          return (
            <a
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary hover:underline"
            >
              {children}
            </a>
          );
        },
      }}
    >
      {content}
    </ReactMarkdown>
    </div>
  );
}
