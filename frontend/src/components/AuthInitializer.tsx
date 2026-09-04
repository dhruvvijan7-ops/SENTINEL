import { useEffect } from "react";

import { authService } from "@/services/authService";
import { useAuthStore } from "@/store/authStore";

export default function AuthInitializer({ children }: { children: React.ReactNode }) {
  const token = useAuthStore((s) => s.token);
  const setUser = useAuthStore((s) => s.setUser);
  const logout = useAuthStore((s) => s.logout);

  useEffect(() => {
    if (!token) return;

    let cancelled = false;

    authService
      .getCurrentUser()
      .then((user) => {
        if (!cancelled) {
          setUser(user as ReturnType<typeof useAuthStore.getState>["user"]);
        }
      })
      .catch(() => {
        if (!cancelled) {
          logout();
        }
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return <>{children}</>;
}
