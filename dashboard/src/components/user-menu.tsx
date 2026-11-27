"use client";

import { LogOut, User } from "lucide-react";
import { signOut, useSession } from "next-auth/react";

export function UserMenu() {
  const { data } = useSession();
  const user = data?.user;

  if (!user) return null;

  return (
    <div className="flex items-center gap-2 px-3 py-1.5">
      {user.image ? (
        <span
          role="img"
          aria-label={user.name ? `${user.name} profile` : "User profile"}
          className="h-6 w-6 rounded-full bg-cover bg-center"
          style={{ backgroundImage: `url(${JSON.stringify(user.image)})` }}
        />
      ) : (
        <User className="h-4 w-4 text-muted-foreground" />
      )}
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium truncate">{user.name || user.email || "Signed in"}</p>
      </div>
        <button
          type="button"
          onClick={() => signOut({ callbackUrl: "/auth/signin" })}
          className="grid size-11 shrink-0 place-items-center rounded-md text-muted-foreground hover:bg-accent hover:text-foreground"
          aria-label="Sign out"
          title="Sign out"
        >
          <LogOut className="h-3.5 w-3.5" />
        </button>
    </div>
  );
}
