import { prisma } from "@/lib/prisma";
import * as yaml from "js-yaml";
import * as fs from "fs";
import * as path from "path";
import { assertAegifyRuleId, resolveWithinDirectory } from "@/lib/rule-path";

interface YamlRule {
  id: string;
  name: string;
  description?: string;
  severity: string;
  confidence?: number;
  languages?: string[];
  cwe_id?: number | null;
  owasp_category?: string | null;
  patterns?: unknown[];
  taint?: unknown;
  defense_patterns?: string[];
  message?: string;
}

interface YamlRuleFile {
  rules: YamlRule[];
}

function getRulesDir(): string {
  // Rules live at the project root: ../../rules relative to dashboard/
  return path.resolve(process.cwd(), "..", "rules");
}

function findYamlFiles(dir: string): string[] {
  const results: string[] = [];
  if (!fs.existsSync(dir)) return results;

  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...findYamlFiles(fullPath));
    } else if (
      entry.isFile() &&
      (entry.name.endsWith(".yml") || entry.name.endsWith(".yaml"))
    ) {
      results.push(fullPath);
    }
  }
  return results;
}

export async function syncYamlToDb(): Promise<{ synced: number; errors: string[] }> {
  const rulesDir = getRulesDir();
  const yamlFiles = findYamlFiles(rulesDir);
  let synced = 0;
  const errors: string[] = [];

  for (const filePath of yamlFiles) {
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      const parsed = yaml.load(content) as YamlRuleFile;
      if (!parsed?.rules || !Array.isArray(parsed.rules)) continue;

      // Relative path from rules dir
      const relPath = path.relative(rulesDir, filePath);

      for (const rule of parsed.rules) {
        if (!rule.id || !rule.name) continue;

        // Serialize the individual rule back to YAML for storage
        const ruleYaml = yaml.dump(rule, { lineWidth: 120, noRefs: true });
        const languages = Array.isArray(rule.languages) ? rule.languages.join(", ") : "";

        try {
          await prisma.rule.upsert({
            where: { id: rule.id },
            create: {
              id: rule.id,
              name: rule.name,
              severity: rule.severity || "medium",
              cweId: rule.cwe_id ?? null,
              owaspCategory: rule.owasp_category ?? null,
              languages,
              enabled: true,
              description: rule.description || "",
              yamlContent: ruleYaml,
              sourceFile: relPath,
            },
            update: {
              name: rule.name,
              severity: rule.severity || "medium",
              cweId: rule.cwe_id ?? null,
              owaspCategory: rule.owasp_category ?? null,
              languages,
              description: rule.description || "",
              yamlContent: ruleYaml,
              sourceFile: relPath,
            },
          });
          synced++;
        } catch (e) {
          errors.push(`Rule ${rule.id}: ${e instanceof Error ? e.message : String(e)}`);
        }
      }
    } catch (e) {
      errors.push(`File ${filePath}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  return { synced, errors };
}

export async function syncDbToYaml(ruleId: string): Promise<{ success: boolean; error?: string }> {
  try {
    assertAegifyRuleId(ruleId);
  } catch (error) {
    return { success: false, error: error instanceof Error ? error.message : "Invalid rule ID" };
  }
  const rule = await prisma.rule.findUnique({ where: { id: ruleId } });
  if (!rule) return { success: false, error: "Rule not found" };

  const rulesDir = getRulesDir();

  // If rule has a sourceFile, write back to that file
  // Otherwise, create a new file based on rule ID
  let targetFile: string;
  if (rule.sourceFile) {
    try {
      targetFile = resolveWithinDirectory(rulesDir, rule.sourceFile);
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : "Invalid rule source path",
      };
    }
  } else {
    // Generate a file path from the rule ID
    const category = ruleId.toLowerCase().replace(/^aeg-/, "").split("-")[0];
    const relativeTarget = path.join(category, `${ruleId.toLowerCase()}.yml`);
    targetFile = resolveWithinDirectory(rulesDir, relativeTarget);
    const dir = path.dirname(targetFile);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  }

  try {
    // Parse the current YAML content of the rule
    let ruleObj: YamlRule;
    if (rule.yamlContent) {
      ruleObj = yaml.load(rule.yamlContent) as YamlRule;
    } else {
      ruleObj = {
        id: rule.id,
        name: rule.name,
        severity: rule.severity,
        description: rule.description || undefined,
        cwe_id: rule.cweId,
        owasp_category: rule.owaspCategory,
        languages: rule.languages ? rule.languages.split(",").map((l) => l.trim()) : undefined,
      };
    }

    // If the file already exists, try to update just this rule in the file
    if (fs.existsSync(/* turbopackIgnore: true */ targetFile)) {
      const existing = yaml.load(
        fs.readFileSync(/* turbopackIgnore: true */ targetFile, "utf-8"),
      ) as YamlRuleFile;
      if (existing?.rules && Array.isArray(existing.rules)) {
        const idx = existing.rules.findIndex((r) => r.id === ruleId);
        if (idx >= 0) {
          existing.rules[idx] = ruleObj;
        } else {
          existing.rules.push(ruleObj);
        }
        fs.writeFileSync(targetFile, yaml.dump(existing, { lineWidth: 120, noRefs: true }));
        return { success: true };
      }
    }

    // Otherwise write a new file
    const output: YamlRuleFile = { rules: [ruleObj] };
    const dir = path.dirname(targetFile);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(targetFile, yaml.dump(output, { lineWidth: 120, noRefs: true }));

    // Update sourceFile in DB
    const relPath = path.relative(rulesDir, targetFile);
    await prisma.rule.update({
      where: { id: ruleId },
      data: { sourceFile: relPath },
    });

    return { success: true };
  } catch (e) {
    return { success: false, error: e instanceof Error ? e.message : String(e) };
  }
}
