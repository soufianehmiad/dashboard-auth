import { api } from './client';
import type { ServerInfo } from '../types';

export const dashboardApi = {
  getServerInfo: async (): Promise<ServerInfo> => {
    const response = await api.get<ServerInfo>('/server-info');
    return response.data;
  },
};
