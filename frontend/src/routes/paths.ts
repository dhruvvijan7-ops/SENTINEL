export const ROUTES = {
  dashboard: "/dashboard",
  monitoring: "/monitoring",
  investigation: "/monitoring/:detectionId",
  analysis: "/analysis",
  alerts: "/alerts",
  network: "/network",
  settings: "/settings",
  adminUsers: "/admin/users",
  adminAuditLogs: "/admin/audit-logs",
  login: "/login",
  register: "/register",
  forgotPassword: "/forgot-password",
} as const;
