import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const statusConfig: Record<string, { color: string; label: string }> = {
  open: {
    color: "bg-[var(--status-open-bg)] text-[var(--status-open)] border-[var(--status-open)]/20",
    label: "Open",
  },
  triaged: {
    color: "bg-[var(--status-triaged-bg)] text-[var(--status-triaged)] border-[var(--status-triaged)]/20",
    label: "Triaged",
  },
  in_progress: {
    color: "bg-[var(--status-in-progress-bg)] text-[var(--status-in-progress)] border-[var(--status-in-progress)]/20",
    label: "In Progress",
  },
  confirmed: {
    color: "bg-[var(--status-confirmed-bg)] text-[var(--status-confirmed)] border-[var(--status-confirmed)]/20",
    label: "Confirmed",
  },
  false_positive: {
    color: "bg-[var(--status-false-positive-bg)] text-[var(--status-false-positive)] border-[var(--status-false-positive)]/20",
    label: "False Positive",
  },
  fixed: {
    color: "bg-[var(--status-fixed-bg)] text-[var(--status-fixed)] border-[var(--status-fixed)]/20",
    label: "Fixed",
  },
};

export function StatusBadge({ status }: { status: string }) {
  const config = statusConfig[status] || statusConfig.open;
  return (
    <Badge variant="outline" className={cn("text-xs", config.color)}>
      {config.label}
    </Badge>
  );
}
