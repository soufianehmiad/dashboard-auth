import { api } from './client';
import type { LoginRequest, LoginResponse, User } from '../types';

export const authApi = {
  login: async (credentials: LoginRequest): Promise<LoginResponse> => {
    const response = await api.post<LoginResponse>('/login', credentials);
    return response.data;
  },

  logout: async (): Promise<void> => {
    await api.post('/logout');
  },

  verifyToken: async (): Promise<{ user: User }> => {
    const response = await api.get<{ user: User }>('/verify');
    return response.data;
  },

  changePassword: async (currentPassword: string, newPassword: string): Promise<{ success: boolean }> => {
    const response = await api.post('/change-password', {
      currentPassword,
      newPassword,
    });
    return response.data;
  },

  changeDisplayName: async (displayName: string): Promise<{ success: boolean }> => {
    const response = await api.post('/change-display-name', {
      displayName,
    });
    return response.data;
  },
};
