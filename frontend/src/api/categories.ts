import { api } from './client';
import type { Category, CreateCategoryRequest, UpdateCategoryRequest } from '../types';

export const categoriesApi = {
  getAll: async (): Promise<Category[]> => {
    const response = await api.get<Category[]>('/categories');
    return response.data;
  },

  create: async (category: CreateCategoryRequest): Promise<{ success: boolean }> => {
    const response = await api.post('/categories', category);
    return response.data;
  },

  update: async (id: string, category: UpdateCategoryRequest): Promise<{ success: boolean }> => {
    const response = await api.put(`/categories/${id}`, category);
    return response.data;
  },

  delete: async (id: string): Promise<{ success: boolean }> => {
    const response = await api.delete(`/categories/${id}`);
    return response.data;
  },
};
