"use client";

import { useEffect, useState } from "react";
import { LogOut, User } from "lucide-react";

interface SessionUser {
  name?: string | null;
  email?: string | null;
  image?: string | null;
}

export function UserMenu() {
  const [user, setUser] = useState<SessionUser | null>(null);

  useEffect(() => {
    fetch("/api/auth/session")
      .then((r) => r.json())
      .then((data) => {
        if (data?.user) setUser(data.user);
      })
      .catch(() => {});
  }, []);

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
        <p className="text-xs font-medium truncate">{user.name || user.email}</p>
      </div>
      <form action="/api/auth/signout" method="POST">
        <button
          type="submit"
          className="text-muted-foreground hover:text-foreground transition-colors"
          title="Sign out"
        >
          <LogOut className="h-3.5 w-3.5" />
        </button>
      </form>
    </div>
  );
}
