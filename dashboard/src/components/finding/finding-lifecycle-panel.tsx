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
  return (
    <div className="space-y-3">
      <dl className="finding-facts">
        <div><dt>Baseline change</dt><dd className={baselineState === "regressed" ? "font-semibold text-destructive" : "font-medium"}>
          {baselineState ? baselineState[0].toUpperCase() + baselineState.slice(1).replaceAll("_", " ") : "Unrecorded"}
        </dd></div>
        {identity && <>
          <div><dt>Occurrences</dt><dd className="tabular-nums">{identity.occurrenceCount}</dd></div>
          <div><dt>First seen</dt><dd><time dateTime={identity.firstSeenAt}>{new Date(identity.firstSeenAt).toLocaleString()}</time></dd></div>
          <div><dt>Last seen</dt><dd><time dateTime={identity.lastSeenAt}>{new Date(identity.lastSeenAt).toLocaleString()}</time></dd></div>
          {identity.absentAt && <div><dt>Absent since</dt><dd><time dateTime={identity.absentAt}>{new Date(identity.absentAt).toLocaleString()}</time></dd></div>}
        </>}
      </dl>
      {!identity && <p className="text-sm text-muted-foreground">No linked observations in other scans.</p>}
      {identity?.triageReason && <div className="space-y-1 text-sm">
        <h3 className="font-semibold">Current triage rationale</h3>
        <p className="whitespace-pre-wrap wrap-anywhere">{identity.triageReason}</p>
        <p className="text-xs text-muted-foreground">{[identity.triageActor, identity.triageExpiresAt && `Expires ${new Date(identity.triageExpiresAt).toLocaleDateString()}`].filter(Boolean).join(" · ")}</p>
      </div>}
      {identity && identity.triageEvents.length > 0 && <div>
        <h3 className="font-semibold text-sm">Audit trail</h3>
        <ol className="mt-2 max-h-56 overflow-auto border-t border-border" aria-label="Triage events" tabIndex={0}>
          {identity.triageEvents.map((event) => <li key={event.id} className="space-y-1 border-b border-border py-2 text-sm wrap-anywhere">
            <p>{event.fromStatus.replaceAll("_", " ")} → {event.toStatus.replaceAll("_", " ")}</p>
            {event.reason && <p className="whitespace-pre-wrap">{event.reason}</p>}
            <p className="text-xs text-muted-foreground">{event.actor} · <time dateTime={event.createdAt}>{new Date(event.createdAt).toLocaleString()}</time></p>
          </li>)}
        </ol>
      </div>}
    </div>
  );
}
