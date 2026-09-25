import { apiClient } from "@/services/apiClient";
import type { AuthResponse, LoginCredentials, RegisterData, ResetPasswordData, User } from "@/types/auth";

export const authService = {
  login: (credentials: LoginCredentials) =>
    apiClient.post<AuthResponse>("/auth/login", credentials),

  register: (data: RegisterData) =>
    apiClient.post<AuthResponse>("/auth/register", data),

  getCurrentUser: () =>
    apiClient.get<User>("/auth/me"),

  logout: () =>
    apiClient.post<{ message: string }>("/auth/logout", {}),

  forgotPassword: (email: string) =>
    apiClient.post<{ message: string }>("/auth/forgot-password", { email }),

  resetPassword: (data: ResetPasswordData) =>
    apiClient.post<{ message: string }>("/auth/reset-password", data),
};