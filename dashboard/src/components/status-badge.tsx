import { BookmarkCheck, CheckCheck, Circle, CircleCheck, CircleDot, CircleMinus, Clock3, type LucideIcon } from "lucide-react";

const states: Record<string, { label: string; icon: LucideIcon; color?: string }> = {
  open: { label: "Open", icon: Circle },
  triaged: { label: "Triaged", icon: BookmarkCheck },
  in_progress: { label: "In progress", icon: CircleDot, color: "text-[var(--status-in-progress)]" },
  confirmed: { label: "Confirmed", icon: CheckCheck, color: "text-primary" },
  false_positive: { label: "False positive", icon: CircleMinus },
  accepted_risk: { label: "Accepted risk", icon: Clock3 },
  fixed: { label: "Fixed", icon: CircleCheck, color: "text-primary" },
};

export const findingStatusOptions = Object.entries(states).map(([value, { label }]) => ({ value, label }));

export function StatusBadge({ status }: { status: string }) {
  const { label, icon: Icon, color } = Object.hasOwn(states, status)
    ? states[status]
    : { label: status || "Unclassified", icon: Circle, color: undefined };
  return <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-xs text-muted-foreground">
    <Icon aria-hidden className={"size-3.5 shrink-0 " + (color ?? "")} />{label}
  </span>;
}
