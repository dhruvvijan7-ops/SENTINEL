import { apiClient } from "@/services/apiClient";
import type { AuthResponse, LoginCredentials, RegisterData } from "@/types/auth";

export const authService = {
  login: (credentials: LoginCredentials) =>
    apiClient.post<AuthResponse>("/auth/login", credentials),

  register: (data: RegisterData) =>
    apiClient.post<AuthResponse>("/auth/register", data),

  getCurrentUser: () =>
    apiClient.get<{ id: string; email: string; name: string; role: string }>("/auth/me"),

  logout: () =>
    apiClient.post<{ message: string }>("/auth/logout", {}),

  forgotPassword: (email: string) =>
    apiClient.post<{ message: string }>("/auth/forgot-password", { email }),

  resetPassword: (token: string, newPassword: string) =>
    apiClient.post<{ message: string }>("/auth/reset-password", { token, new_password: newPassword }),
};
