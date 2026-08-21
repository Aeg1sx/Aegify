import { NextResponse } from "next/server";
import { getSlackConfig } from "@/lib/settings";

export async function POST() {
  const config = await getSlackConfig();

  if (!config.webhookUrl) {
    return NextResponse.json(
      { error: "Slack webhook URL not configured" },
      { status: 400 }
    );
  }

  try {
    const res = await fetch(config.webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        text: "CodeGuard SAST - Test notification. Slack integration is working.",
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
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Failed to send" },
      { status: 500 }
    );
  }
}
