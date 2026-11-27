"use client";

import { useSearchParams } from "next/navigation";
import { useMemo, useSyncExternalStore } from "react";

const changed = "aegify:search-changed";

function subscribe(notify: () => void) {
  window.addEventListener("popstate", notify);
  window.addEventListener(changed, notify);
  return () => {
    window.removeEventListener("popstate", notify);
    window.removeEventListener(changed, notify);
  };
}

function currentSearch() {
  return window.location.search;
}

// A router transition may complete after a second keystroke. Filter controls
// and their results both need the query from the current history entry.
export function useHistorySearch() {
  const initial = useSearchParams();
  const query = useSyncExternalStore(subscribe, currentSearch, () => initial.toString());
  return useMemo(() => new URLSearchParams(query), [query]);
}

export function replaceHistorySearch(url: URL) {
  window.history.replaceState(null, "", url);
  window.dispatchEvent(new Event(changed));
}
