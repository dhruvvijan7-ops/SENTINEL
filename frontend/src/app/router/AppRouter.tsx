import {
  BrowserRouter,
  Route,
  Routes,
} from "react-router-dom";

import DashboardLayout from "@/layouts/DashboardLayout";
import AuthLayout from "@/layouts/AuthLayout";

import ProtectedRoute from "@/app/router/ProtectedRoute";
import AdminRoute from "@/app/router/AdminRoute";
import AuditRoute from "@/app/router/AuditRoute";

import LandingPage from "@/features/landing/pages/LandingPage";
import DashboardPage from "@/features/dashboard/pages/DashboardPage";
import MonitoringPage from "@/features/monitoring/pages/MonitoringPage";
import InvestigationPage from "@/features/monitoring/pages/InvestigationPage";
import AnalysisPage from "@/features/analysis/pages/AnalysisPage";
import AlertsPage from "@/features/alerts/pages/AlertsPage";
import NetworkPage from "@/features/network/pages/NetworkPage";
import SettingsPage from "@/features/settings/pages/SettingsPage";
import UsersPage from "@/features/admin/pages/UsersPage";
import AuditLogsPage from "@/features/admin/pages/AuditLogsPage";

import LoginPage from "@/features/auth/pages/LoginPage";
import RegisterPage from "@/features/auth/pages/RegisterPage";
import ForgotPasswordPage from "@/features/auth/pages/ForgotPasswordPage";
import ResetPasswordPage from "@/features/auth/pages/ResetPasswordPage";

import NotFoundPage from "@/features/common/pages/NotFoundPage";

import { ROUTES } from "@/routes/paths";

export default function AppRouter() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public Landing */}
        <Route path="/" element={<LandingPage />} />

        {/* Protected Application */}
        <Route element={<ProtectedRoute />}>
          <Route element={<DashboardLayout />}>
            <Route
              path={ROUTES.dashboard}
              element={<DashboardPage />}
            />

            <Route
              path={ROUTES.monitoring}
              element={<MonitoringPage />}
            />

            <Route
              path={ROUTES.investigation}
              element={<InvestigationPage />}
            />

            <Route
              path={ROUTES.analysis}
              element={<AnalysisPage />}
            />

            <Route
              path={ROUTES.alerts}
              element={<AlertsPage />}
            />

            <Route
              path={ROUTES.network}
              element={<NetworkPage />}
            />

            <Route
              path={ROUTES.settings}
              element={<SettingsPage />}
            />

            {/* Admin-only routes */}
            <Route element={<AdminRoute />}>
              <Route
                path={ROUTES.adminUsers}
                element={<UsersPage />}
              />
            </Route>

            {/* Admin or analyst routes (audit logs, read-only for analysts) */}
            <Route element={<AuditRoute />}>
              <Route
                path={ROUTES.adminAuditLogs}
                element={<AuditLogsPage />}
              />
            </Route>
          </Route>
        </Route>

        {/* Authentication */}
        <Route element={<AuthLayout />}>
          <Route
            path={ROUTES.login}
            element={<LoginPage />}
          />

          <Route
            path={ROUTES.register}
            element={<RegisterPage />}
          />

          <Route
            path={ROUTES.forgotPassword}
            element={<ForgotPasswordPage />}
          />

          <Route
            path={ROUTES.resetPassword}
            element={<ResetPasswordPage />}
          />
        </Route>

        {/* Not Found */}
        <Route
          path="*"
          element={<NotFoundPage />}
        />
      </Routes>
    </BrowserRouter>
  );
}
