export interface User {
  id: string;
  email: string;
  name: string;
  role: "admin" | "analyst" | "viewer";
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterData {
  name: string;
  email: string;
  password: string;
}

export interface AuthResponse {
  user: User;
  message: string;
}

export interface ResetPasswordData {
  token: string;
  new_password: string;
}