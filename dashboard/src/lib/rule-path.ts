import * as fs from "fs";
import * as path from "path";

const AEGIFY_RULE_ID = /^AEG-[A-Z0-9]+(?:-[A-Z0-9]+)*$/;

export function assertAegifyRuleId(ruleId: string): void {
  if (!AEGIFY_RULE_ID.test(ruleId)) {
    throw new Error("Rule ID must use the AEG-* identifier format");
  }
}

export function resolveWithinDirectory(root: string, candidate: string): string {
  if (!candidate || path.isAbsolute(candidate)) {
    throw new Error("Rule source path must be relative");
  }

  const resolvedRoot = path.resolve(root);
  const resolvedTarget = path.resolve(resolvedRoot, candidate);
  const relative = path.relative(resolvedRoot, resolvedTarget);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw new Error("Rule source path escapes the rules directory");
  }

  let current = resolvedRoot;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) {
      throw new Error("Rule source path must not traverse symbolic links");
    }
  }
  return resolvedTarget;
}
