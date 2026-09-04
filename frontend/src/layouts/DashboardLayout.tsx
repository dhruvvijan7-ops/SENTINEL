import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  Activity,
  FileUp,
  Bell,
  ChevronRight,
  ClipboardList,
  LayoutDashboard,
  LogOut,
  Menu,
  Settings,
  ShieldCheck,
  User,
  Users,
  Network,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";

import { ROUTES } from "@/routes/paths";
import { useAuthStore } from "@/store/authStore";
import { alertService } from "@/services/alertService";

const navigationItems = [
  {
    label: "Overview",
    path: ROUTES.dashboard,
    icon: LayoutDashboard,
  },
  {
    label: "Monitoring",
    path: ROUTES.monitoring,
    icon: Activity,
  },
  {
    label: "Analysis",
    path: ROUTES.analysis,
    icon: FileUp,
  },
];

function Navigation() {
  const user = useAuthStore((state) => state.user);
  const isAdmin = user?.role === "admin";
  const canViewAudit = isAdmin || user?.role === "analyst";

  const newAlertsQuery = useQuery({
    queryKey: ["alerts-count"],
    queryFn: () => alertService.getAlerts("new"),
  });
  const newAlertCount = newAlertsQuery.data?.length ?? 0;

  return (
    <nav className="flex flex-col gap-1">
      <p className="ops-section-label mb-2 px-3 text-[10px] font-semibold uppercase tracking-[0.18em]">
        Security Operations
      </p>

      {navigationItems.map((item) => {
        const Icon = item.icon;

        return (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === ROUTES.dashboard}
            className={({ isActive }) =>
              [
                "ops-nav-link group flex items-center gap-3 rounded-xl px-3 py-2.5",
                "text-sm font-medium transition-all duration-200",
                isActive
                  ? "ops-nav-link-active"
                  : "",
              ].join(" ")
            }
          >
            {({ isActive }) => (
              <>
                <Icon
                  className={[
                    "size-[17px] transition-colors",
                    isActive ? "" : "ops-muted group-hover:text-white",
                  ].join(" ")}
                />

                <span className="flex-1">{item.label}</span>

                {isActive && (
                  <ChevronRight className="size-3.5 text-primary" />
                )}
              </>
            )}
          </NavLink>
        );
      })}

      <p className="ops-section-label mb-2 mt-7 px-3 text-[10px] font-semibold uppercase tracking-[0.18em]">
        Systems
      </p>

      <NavLink
        to={ROUTES.alerts}
        className={({ isActive }) =>
          [
            "ops-nav-link group flex items-center gap-3 rounded-xl px-3 py-2.5",
            "text-sm font-medium transition-all duration-200",
            isActive ? "ops-nav-link-active" : "",
          ].join(" ")
        }
      >
        {({ isActive }) => (
          <>
            <Bell
              className={[
                "size-[17px] transition-colors",
                isActive ? "" : "ops-muted group-hover:text-white",
              ].join(" ")}
            />
            <span className="flex-1">Alerts</span>
            {newAlertCount > 0 && (
              <span className="ml-auto rounded-full bg-[#FF3B30]/10 px-1.5 py-0.5 text-[10px] font-semibold text-[#FF3B30]">
                {newAlertCount}
              </span>
            )}
            {isActive && (
              <ChevronRight className="size-3.5 text-primary" />
            )}
          </>
        )}
      </NavLink>

      <NavLink
        to={ROUTES.network}
        className={({ isActive }) =>
          [
            "ops-nav-link group flex items-center gap-3 rounded-xl px-3 py-2.5",
            "text-sm font-medium transition-all duration-200",
            isActive ? "ops-nav-link-active" : "",
          ].join(" ")
        }
      >
        {({ isActive }) => (
          <>
            <Network
              className={[
                "size-[17px] transition-colors",
                isActive ? "" : "ops-muted group-hover:text-white",
              ].join(" ")}
            />
            <span className="flex-1">Network</span>
            {isActive && (
              <ChevronRight className="size-3.5 text-primary" />
            )}
          </>
        )}
      </NavLink>

      <NavLink
        to={ROUTES.settings}
        className={({ isActive }) =>
          [
            "ops-nav-link group flex items-center gap-3 rounded-xl px-3 py-2.5",
            "text-sm font-medium transition-all duration-200",
            isActive ? "ops-nav-link-active" : "",
          ].join(" ")
        }
      >
        {({ isActive }) => (
          <>
            <Settings
              className={[
                "size-[17px] transition-colors",
                isActive ? "" : "ops-muted group-hover:text-white",
              ].join(" ")}
            />
            <span className="flex-1">Settings</span>
            {isActive && (
              <ChevronRight className="size-3.5 text-primary" />
            )}
          </>
        )}
      </NavLink>

      {isAdmin && (
        <>
          <p className="ops-section-label mb-2 mt-7 px-3 text-[10px] font-semibold uppercase tracking-[0.18em]">
            Administration
          </p>

          <NavLink
            to={ROUTES.adminUsers}
            className={({ isActive }) =>
              [
                "ops-nav-link group flex items-center gap-3 rounded-xl px-3 py-2.5",
                "text-sm font-medium transition-all duration-200",
                isActive ? "ops-nav-link-active" : "",
              ].join(" ")
            }
          >
            {({ isActive }) => (
              <>
                <Users
                  className={[
                    "size-[17px] transition-colors",
                    isActive ? "" : "ops-muted group-hover:text-white",
                  ].join(" ")}
                />
                <span className="flex-1">Users</span>
                {isActive && (
                  <ChevronRight className="size-3.5 text-primary" />
                )}
              </>
            )}
          </NavLink>
        </>
      )}

      {canViewAudit && (
          <NavLink
            to={ROUTES.adminAuditLogs}
            className={({ isActive }) =>
              [
                "ops-nav-link group flex items-center gap-3 rounded-xl px-3 py-2.5",
                "text-sm font-medium transition-all duration-200",
                isActive ? "ops-nav-link-active" : "",
              ].join(" ")
            }
          >
            {({ isActive }) => (
              <>
                <ClipboardList
                  className={[
                    "size-[17px] transition-colors",
                    isActive ? "" : "ops-muted group-hover:text-white",
                  ].join(" ")}
                />
                <span className="flex-1">Audit Logs</span>
                {isActive && (
                  <ChevronRight className="size-3.5 text-primary" />
                )}
              </>
            )}
          </NavLink>
      )}
    </nav>
  );
}

function Brand() {
  return (
    <div className="flex items-center gap-3">
      <div className="relative flex size-9 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-lg shadow-orange-950/20">
        <ShieldCheck className="size-5" />

        <span className="absolute -right-0.5 -top-0.5 size-2 rounded-full bg-[#22C55E] ring-2 ring-card" />
      </div>

      <div className="leading-none">
        <p className="font-semibold tracking-tight">
          Sentinel
        </p>

        <p className="ops-muted mt-1 text-[9px] font-medium uppercase tracking-[0.2em]">
          LIGHT-HIDS
        </p>
      </div>
    </div>
  );
}

function SystemStatus() {
  return (
    <div className="rounded-xl border bg-card p-3">
      <div className="flex items-center gap-2">
        <span className="relative flex size-2">
          <span className="absolute inline-flex size-full animate-ping rounded-full bg-[#22C55E] opacity-60" />
          <span className="relative inline-flex size-2 rounded-full bg-[#22C55E]" />
        </span>

        <span className="text-xs font-medium text-white">
          Analysis Engine
        </span>
      </div>

      <div className="mt-2 flex items-center justify-between">
        <span className="ops-muted text-[11px]">
          Status
        </span>

                <span className="text-[11px] font-medium text-[#F5C542]">
                  Model pending
        </span>
      </div>
    </div>
  );
}

function UserSection() {
  const navigate = useNavigate();
  const user = useAuthStore((state) => state.user);
  const logout = useAuthStore((state) => state.logout);

  function handleLogout() {
    logout();
    navigate(ROUTES.login, { replace: true });
  }

  return (
    <div className="border-t border-border p-3">
      <div className="flex items-center gap-3 rounded-lg px-2 py-2">
        <div className="flex size-8 shrink-0 items-center justify-center rounded-full bg-primary/10 text-primary ring-1 ring-primary/20">
          <User className="size-4" />
        </div>

        <div className="min-w-0 flex-1">
          <p className="truncate text-xs font-medium text-white">
            {user?.name ?? "Security Analyst"}
          </p>

          <p className="ops-muted truncate text-[10px]">
            {user?.role ?? "analyst"}
          </p>
        </div>

        <Button
          variant="ghost"
          size="icon"
          className="ops-muted size-8 shrink-0 hover:bg-secondary hover:text-[#FF3B30]"
          onClick={handleLogout}
          aria-label="Log out"
        >
          <LogOut className="size-4" />
        </Button>
      </div>
    </div>
  );
}

export default function DashboardLayout() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <div className="flex min-h-screen">
        {/* Desktop Sidebar */}
        <aside className="ops-sidebar hidden w-[250px] shrink-0 border-r md:flex md:flex-col">
          <div className="flex h-[68px] items-center border-b border-border px-5">
            <Brand />
          </div>

          <div className="flex-1 overflow-y-auto px-3 py-5">
            <Navigation />
          </div>

          <div className="px-3 pb-3">
            <SystemStatus />
          </div>

          <UserSection />
        </aside>

        {/* Main */}
        <div className="flex min-w-0 flex-1 flex-col">
          <header className="ops-header sticky top-0 z-20 flex h-[68px] items-center border-b px-4 backdrop-blur-xl md:px-6">
            {/* Mobile navigation */}
            <div className="md:hidden">
              <Sheet>
                <SheetTrigger asChild>
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label="Open navigation"
                  >
                    <Menu className="size-5" />
                  </Button>
                </SheetTrigger>

                <SheetContent
                  side="left"
                  className="ops-sidebar w-[270px] p-0"
                >
                  <SheetHeader className="border-b border-border px-5 py-5 text-left">
                    <SheetTitle>
                      <Brand />
                    </SheetTitle>
                  </SheetHeader>

                  <div className="p-3">
                    <Navigation />
                  </div>

                  <div className="absolute bottom-0 w-full p-3">
                    <SystemStatus />
                  </div>
                </SheetContent>
              </Sheet>
            </div>

            {/* Breadcrumb */}
            <div className="ml-3 hidden items-center gap-2 text-sm md:flex">
              <span className="text-muted-foreground">
                Sentinel
              </span>

              <ChevronRight className="size-3.5 text-muted-foreground/50" />

              <span className="font-medium">
                Security Operations
              </span>
            </div>

            <div className="ml-auto flex items-center gap-2">
              {/* Engine status */}
              <div className="hidden items-center gap-2 rounded-full border border-[#F5C542]/30 bg-[#F5C542]/10 px-3 py-1.5 sm:flex">
                <span className="relative flex size-1.5">
                  <span className="absolute inline-flex size-full animate-ping rounded-full bg-[#22C55E] opacity-60" />
                  <span className="relative inline-flex size-1.5 rounded-full bg-[#22C55E]" />
                </span>

                <span className="text-[11px] font-medium text-[#F5C542]">
                  Ingestion ready
                </span>
              </div>

              <Button
                variant="ghost"
                size="icon"
                className="size-9 text-muted-foreground"
                aria-label="Notifications"
              >
                <Bell className="size-4" />
              </Button>

              <div className="flex size-8 items-center justify-center rounded-full bg-primary/10 text-primary">
                <User className="size-4" />
              </div>
            </div>
          </header>

          {/* Page content */}
          <main className="sentinel-grid min-h-[calc(100vh-68px)] flex-1">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  );
}
