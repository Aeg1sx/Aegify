import Link from "next/link";
import { ShieldCheck } from "lucide-react";

export function WorkspaceBrand({ signIn = false, onNavigate }: { signIn?: boolean; onNavigate?: () => void }) {
  return <Link href={signIn ? "/auth/signin" : "/"} onClick={onNavigate} aria-label={signIn ? "Aegify sign in" : "Aegify overview"} className="inline-flex min-h-11 items-center gap-2.5">
    <ShieldCheck aria-hidden className="size-7 shrink-0 text-primary" strokeWidth={1.8} />
    <span className="text-[1.45rem] font-semibold tracking-[-0.045em] text-foreground">Aegify</span>
  </Link>;
}
