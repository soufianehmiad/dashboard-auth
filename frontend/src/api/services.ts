import { api } from './client';
import type { Service, CreateServiceRequest, UpdateServiceRequest, ServiceStatus } from '../types';

export const servicesApi = {
  getAll: async (): Promise<Service[]> => {
    const response = await api.get<Service[]>('/services');
    return response.data;
  },

  getStatus: async (): Promise<Record<string, ServiceStatus>> => {
    const response = await api.get<Record<string, ServiceStatus>>('/status');
    return response.data;
  },

  create: async (service: CreateServiceRequest): Promise<{ success: boolean; id: number }> => {
    const response = await api.post('/services', service);
    return response.data;
  },

  update: async (id: number, service: UpdateServiceRequest): Promise<{ success: boolean }> => {
    const response = await api.put(`/services/${id}`, service);
    return response.data;
  },

  delete: async (id: number): Promise<{ success: boolean }> => {
    const response = await api.delete(`/services/${id}`);
    return response.data;
  },
};
