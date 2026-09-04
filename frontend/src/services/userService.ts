import { apiClient } from "@/services/apiClient";

export interface UserRecord {
  id: string;
  email: string;
  name: string;
  role: string;
  is_active: boolean;
  created_at: string;
  updated_at: string | null;
}

export interface UserListResponse {
  items: UserRecord[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface UserFilters {
  search?: string;
  role?: string;
  is_active?: boolean;
  page?: number;
  page_size?: number;
}

export const userService = {
  getUsers: async (filters: UserFilters = {}): Promise<UserListResponse> => {
    const params = new URLSearchParams();
    if (filters.page) params.set("page", String(filters.page));
    if (filters.page_size) params.set("page_size", String(filters.page_size));
    if (filters.search) params.set("search", filters.search);
    if (filters.role) params.set("role", filters.role);
    if (filters.is_active !== undefined) params.set("is_active", String(filters.is_active));

    const qs = params.toString();
    return apiClient.get<UserListResponse>(`/users${qs ? `?${qs}` : ""}`);
  },

  getUser: async (userId: string): Promise<UserRecord> => {
    return apiClient.get<UserRecord>(`/users/${userId}`);
  },

  updateUser: async (
    userId: string,
    data: { role?: string; is_active?: boolean },
  ): Promise<UserRecord> => {
    return apiClient.patch<UserRecord>(`/users/${userId}`, data);
  },

  createUser: async (data: {
    name: string;
    email: string;
    password: string;
    role: string;
  }): Promise<UserRecord> => {
    return apiClient.post<UserRecord>("/users", data);
  },
};
