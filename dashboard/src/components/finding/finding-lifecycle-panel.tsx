import { Clock3, History, RotateCcw } from "lucide-react";

interface TriageEvent {
  id: string;
  fromStatus: string;
  toStatus: string;
  reason: string;
  actor: string;
  createdAt: string;
}

export interface FindingIdentityView {
  firstSeenAt: string;
  lastSeenAt: string;
  occurrenceCount: number;
  absentAt: string | null;
  triageReason: string;
  triageActor: string;
  triageExpiresAt: string | null;
  triageEvents: TriageEvent[];
}

export function FindingLifecyclePanel({ baselineState, identity }: {
  baselineState: string;
  identity: FindingIdentityView | null;
}) {
  const tone = baselineState === "regressed" ? "text-red-600 bg-red-500/10"
    : baselineState === "new" ? "text-violet-600 bg-violet-500/10"
      : baselineState === "updated" ? "text-amber-600 bg-amber-500/10"
        : "text-emerald-600 bg-emerald-500/10";
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className={`rounded-full px-2.5 py-1 text-xs font-semibold capitalize ${tone}`}>
          {baselineState}
        </span>
        {identity && <span className="text-xs text-muted-foreground">Seen {identity.occurrenceCount} times</span>}
      </div>
      {identity ? (
        <>
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="rounded-md border p-2"><p className="text-muted-foreground">First seen</p><p className="mt-1">{new Date(identity.firstSeenAt).toLocaleString()}</p></div>
            <div className="rounded-md border p-2"><p className="text-muted-foreground">Last seen</p><p className="mt-1">{new Date(identity.lastSeenAt).toLocaleString()}</p></div>
          </div>
          {identity.triageReason && (
            <div className="rounded-md border bg-muted/30 p-3 text-xs">
              <p className="font-medium">Current triage rationale</p>
              <p className="mt-1 text-muted-foreground">{identity.triageReason}</p>
              <p className="mt-2 text-[10px] text-muted-foreground">{identity.triageActor}{identity.triageExpiresAt ? ` · expires ${new Date(identity.triageExpiresAt).toLocaleDateString()}` : ""}</p>
            </div>
          )}
          {identity.triageEvents.length > 0 && (
            <div>
              <p className="mb-2 flex items-center gap-1 text-xs font-medium"><History className="h-3 w-3" />Audit trail</p>
              <div className="max-h-44 space-y-2 overflow-auto">
                {identity.triageEvents.map((event) => (
                  <div key={event.id} className="border-l-2 pl-3 text-xs">
                    <p>{event.fromStatus} → {event.toStatus}</p>
                    {event.reason && <p className="text-muted-foreground">{event.reason}</p>}
                    <p className="text-[10px] text-muted-foreground">{event.actor} · {new Date(event.createdAt).toLocaleString()}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      ) : (
        <p className="flex items-center gap-2 text-xs text-muted-foreground"><RotateCcw className="h-3 w-3" />Lifecycle starts after a project-linked scan.</p>
      )}
      {identity?.absentAt && <p className="flex items-center gap-1 text-xs text-muted-foreground"><Clock3 className="h-3 w-3" />Absent since {new Date(identity.absentAt).toLocaleString()}</p>}
    </div>
  );
}
