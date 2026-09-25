import { Navigate, Outlet, useLocation } from "react-router-dom";

import { useAuthStore } from "@/store/authStore";
import { ROUTES } from "@/routes/paths";

export default function AdminRoute() {
  const user = useAuthStore((state) => state.user);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const isInitialized = useAuthStore((state) => state.isInitialized);
  const location = useLocation();

  if (!isInitialized) {
    return null;
  }

  if (!isAuthenticated) {
    return (
      <Navigate
        to={ROUTES.login}
        replace
        state={{ from: location }}
      />
    );
  }

  if (user?.role !== "admin") {
    return (
      <Navigate
        to={ROUTES.dashboard}
        replace
      />
    );
  }

  return <Outlet />;
}
