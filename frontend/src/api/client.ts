import axios, { AxiosError } from 'axios';
import type { ApiError } from '../types';

// Create axios instance
export const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // Important for cookies
});

// CSRF token storage
let csrfToken: string | null = null;

// Fetch CSRF token
export async function fetchCsrfToken(): Promise<string> {
  try {
    const response = await axios.get('/api/csrf-token', { withCredentials: true });
    csrfToken = response.data.token;
    return csrfToken;
  } catch (error) {
    console.error('Failed to fetch CSRF token:', error);
    throw error;
  }
}

// Request interceptor to add CSRF token
api.interceptors.request.use(
  async (config) => {
    // For state-changing operations, add CSRF token
    if (config.method && ['post', 'put', 'delete', 'patch'].includes(config.method.toLowerCase())) {
      if (!csrfToken) {
        await fetchCsrfToken();
      }
      if (csrfToken) {
        config.headers['x-csrf-token'] = csrfToken;
      }
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle errors and refresh CSRF token
api.interceptors.response.use(
  (response) => response,
  async (error: AxiosError<ApiError>) => {
    // If CSRF token expired (403), refresh it and retry
    if (error.response?.status === 403 && error.config) {
      try {
        await fetchCsrfToken();
        // Retry the request
        if (error.config.headers) {
          error.config.headers['x-csrf-token'] = csrfToken || '';
        }
        return api.request(error.config);
      } catch {
        return Promise.reject(error);
      }
    }

    // If unauthorized (401), redirect to login
    if (error.response?.status === 401 && window.location.pathname !== '/login') {
      window.location.href = `/login?redirect=${encodeURIComponent(window.location.pathname)}`;
    }

    return Promise.reject(error);
  }
);

// Helper to extract error message
export function getErrorMessage(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const apiError = error.response?.data as ApiError | undefined;
    return apiError?.error || apiError?.message || error.message || 'An error occurred';
  }
  if (error instanceof Error) {
    return error.message;
  }
  return 'An unknown error occurred';
}
