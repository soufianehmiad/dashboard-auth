import { api } from './client';
import type { User, Role } from '../types';

export interface CreateUserRequest {
  username: string;
  password: string;
  displayName?: string | null;
  email?: string | null;
  role: string;
}

export interface UpdateUserRequest {
  displayName?: string | null;
  email?: string | null;
  role?: string;
  isActive?: boolean;
}

export const usersApi = {
  getAll: async (): Promise<User[]> => {
    const response = await api.get<User[]>('/users');
    return response.data;
  },

  getRoles: async (): Promise<Role[]> => {
    const response = await api.get<Role[]>('/roles');
    return response.data;
  },

  create: async (user: CreateUserRequest): Promise<{ success: boolean; id: number }> => {
    const response = await api.post('/users', user);
    return response.data;
  },

  update: async (id: number, user: UpdateUserRequest): Promise<{ success: boolean }> => {
    const response = await api.put(`/users/${id}`, user);
    return response.data;
  },

  delete: async (id: number): Promise<{ success: boolean }> => {
    const response = await api.delete(`/users/${id}`);
    return response.data;
  },

  resetPassword: async (
    id: number,
    newPassword: string,
    requireChange: boolean
  ): Promise<{ success: boolean }> => {
    const response = await api.put(`/users/${id}/password`, {
      newPassword,
      requireChange,
    });
    return response.data;
  },
};
