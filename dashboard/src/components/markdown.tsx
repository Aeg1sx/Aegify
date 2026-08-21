"use client";

import ReactMarkdown from "react-markdown";
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
        code({ className, children, ...props }) {
          const match = /language-(\w+)/.exec(className || "");
          const isInline = !match;
          const codeStr = String(children).replace(/\n$/, "");

          if (isInline) {
            return (
              <code
                className="px-1.5 py-0.5 rounded bg-muted text-sm font-mono"
                {...props}
              >
                {children}
              </code>
            );
          }

          return (
            <CodeHighlight
              code={codeStr}
              language={match?.[1]}
            />
          );
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
