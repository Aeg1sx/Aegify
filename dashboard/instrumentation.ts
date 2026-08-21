export async function register() {
  // Auto-sync YAML rules to DB on server startup
  if (process.env.NEXT_RUNTIME === "nodejs") {
    try {
      const { syncYamlToDb } = await import("@/lib/rule-sync");
      const result = await syncYamlToDb();
      console.log(`[Aegify] Synced ${result.synced} rules from YAML files`);
      if (result.errors.length > 0) {
        console.warn(`[Aegify] Rule sync errors:`, result.errors.slice(0, 5));
      }
    } catch (e) {
      console.error("[Aegify] Rule sync failed:", e);
    }
  }
}
