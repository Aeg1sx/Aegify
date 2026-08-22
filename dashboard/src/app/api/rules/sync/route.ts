import { NextRequest, NextResponse } from "next/server";
import { syncYamlToDb, syncDbToYaml } from "@/lib/rule-sync";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { direction, ruleId } = body;

    if (direction === "yaml-to-db") {
      const result = await syncYamlToDb();
      return NextResponse.json({
        message: `Synced ${result.synced} rules from YAML files`,
        synced: result.synced,
        errors: result.errors,
      });
    }

    if (direction === "db-to-yaml") {
      if (!ruleId) {
        return NextResponse.json({ error: "ruleId required for db-to-yaml sync" }, { status: 400 });
      }
      const result = await syncDbToYaml(ruleId);
      if (!result.success) {
        return NextResponse.json({ error: result.error }, { status: 400 });
      }
      return NextResponse.json({ message: `Rule ${ruleId} saved to YAML` });
    }

    return NextResponse.json({ error: "Invalid direction. Use 'yaml-to-db' or 'db-to-yaml'" }, { status: 400 });
  } catch (error) {
    console.error("Rule sync error:", error);
    return NextResponse.json(
      { error: "Sync failed" },
      { status: 500 },
    );
  }
}
