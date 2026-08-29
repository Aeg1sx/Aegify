import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";

const LANG_EXTENSIONS: Record<string, string> = {
  ".py": "Python",
  ".js": "JavaScript",
  ".ts": "TypeScript",
  ".tsx": "TypeScript",
  ".jsx": "JavaScript",
  ".java": "Java",
  ".go": "Go",
  ".rs": "Rust",
  ".kt": "Kotlin",
  ".swift": "Swift",
  ".rb": "Ruby",
  ".php": "PHP",
  ".c": "C",
  ".cpp": "C++",
  ".cs": "C#",
};

export async function GET() {
  const findings = await prisma.finding.findMany({
    where: { isCurrent: true },
    select: { filePath: true },
    distinct: ["filePath"],
  });

  const langSet = new Set<string>();
  for (const f of findings) {
    const ext = f.filePath.slice(f.filePath.lastIndexOf("."));
    const lang = LANG_EXTENSIONS[ext];
    if (lang) langSet.add(lang);
  }

  return NextResponse.json({ languages: Array.from(langSet).sort() });
}
