import { create } from "zustand";

import { authService } from "@/services/authService";
import type { User } from "@/types/auth";

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isInitialized: boolean;

  login: (user: User) => void;
  logout: () => Promise<void>;
  setUser: (user: User | null) => void;
  setInitialized: (initialized: boolean) => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isAuthenticated: false,
  isInitialized: false,

  login: (user) =>
    set({
      user,
      isAuthenticated: true,
      isInitialized: true,
    }),

  logout: async () => {
    try {
      await authService.logout();
    } catch {
      // Ignore logout failures; local state is cleared regardless.
    } finally {
      set({
        user: null,
        isAuthenticated: false,
        isInitialized: true,
      });
    }
  },

  setUser: (user) =>
    set({
      user,
      isAuthenticated: user !== null,
    }),

  setInitialized: (initialized) =>
    set({ isInitialized: initialized }),
}));