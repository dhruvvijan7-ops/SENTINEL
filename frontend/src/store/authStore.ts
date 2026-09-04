import { create } from "zustand";

import { authService } from "@/services/authService";
import type { User } from "@/types/auth";

const TOKEN_KEY = "sentinel-token";
const USER_KEY = "sentinel-user";

interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;

  login: (user: User, token: string) => void;
  logout: () => Promise<void>;
  setUser: (user: User | null) => void;
}

function loadStoredAuth(): { user: User | null; token: string | null } {
  try {
    const token = localStorage.getItem(TOKEN_KEY);
    const userJson = localStorage.getItem(USER_KEY);
    if (token && userJson) {
      return { token, user: JSON.parse(userJson) as User };
    }
  } catch {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
  }
  return { user: null, token: null };
}

const stored = loadStoredAuth();

export const useAuthStore = create<AuthState>((set) => ({
  user: stored.user,
  token: stored.token,
  isAuthenticated: stored.token !== null,

  login: (user, token) => {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, JSON.stringify(user));
    set({
      user,
      token,
      isAuthenticated: true,
    });
  },

  logout: async () => {
    try {
      await authService.logout();
    } catch {
      // Ignore logout failures; local state is cleared regardless.
    } finally {
      localStorage.removeItem(TOKEN_KEY);
      localStorage.removeItem(USER_KEY);
      set({
        user: null,
        token: null,
        isAuthenticated: false,
      });
    }
  },

  setUser: (user) => {
    if (user) {
      localStorage.setItem(USER_KEY, JSON.stringify(user));
    } else {
      localStorage.removeItem(USER_KEY);
    }
    set({
      user,
      isAuthenticated: user !== null,
    });
  },
}));