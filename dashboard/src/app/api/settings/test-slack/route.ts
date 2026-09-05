import { NextResponse } from "next/server";
import { getSlackConfig } from "@/lib/settings";
import { validateSlackWebhookUrl } from "@/lib/url-validator";

export async function POST() {
  const config = await getSlackConfig();

  if (!config.webhookUrl) {
    return NextResponse.json(
      { error: "Slack webhook URL not configured" },
      { status: 400 }
    );
  }
  const validation = validateSlackWebhookUrl(config.webhookUrl);
  if (!validation.valid) {
    return NextResponse.json({ error: validation.error }, { status: 400 });
  }

  try {
    const res = await fetch(config.webhookUrl, {
      method: "POST",
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: "Aegify - Test notification. Slack integration is working.",
        channel: config.channel,
      }),
    });

    if (!res.ok) {
      return NextResponse.json(
        { error: `Slack returned ${res.status}` },
        { status: 502 }
      );
    }

    return NextResponse.json({ success: true });
  } catch (error) {
    console.error("Slack test notification error:", error);
    return NextResponse.json(
      { error: "Failed to send" },
      { status: 500 }
    );
  }
}
