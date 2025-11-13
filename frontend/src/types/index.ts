// User types
export interface User {
  id: number;
  username: string;
  display_name: string | null;
  email: string | null;
  role: string;
  is_active: boolean;
  require_password_change: boolean;
  last_login_at: string | null;
  created_at: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface LoginResponse {
  success: boolean;
  user: User;
}

// Service types
export interface Service {
  id: number;
  name: string;
  path: string;
  icon_url: string;
  category: string;
  service_type: 'external' | 'proxied' | 'internal';
  proxy_target: string | null;
  api_url: string | null;
  api_key_env: string | null;
  display_order: number;
  enabled: boolean;
  created_at: string;
}

export interface ServiceStatus {
  name: string;
  status: 'online' | 'offline' | 'unknown';
  activity: string | null;
}

export interface CreateServiceRequest {
  name: string;
  path: string;
  icon_url: string;
  category: string;
  service_type: 'external' | 'proxied' | 'internal';
  proxy_target?: string;
  api_url?: string;
  api_key_env?: string;
  display_order?: number;
}

export interface UpdateServiceRequest extends Partial<CreateServiceRequest> {
  enabled?: boolean;
}

// Category types
export interface Category {
  id: string;
  name: string;
  icon: string;
  color: string;
  display_order: number;
  created_at: string;
}

export interface CreateCategoryRequest {
  id: string;
  name: string;
  icon: string;
  color: string;
  display_order?: number;
}

export interface UpdateCategoryRequest extends Partial<CreateCategoryRequest> {}

// Server info types
export interface ServerInfo {
  hostname: string;
  uptime: number;
  cpu_usage: number;
  memory: {
    used_gb: number;
    total_gb: number;
    percent: number;
  };
}

// Dashboard types
export interface DashboardData {
  services: Service[];
  status: Record<string, ServiceStatus>;
  serverInfo: ServerInfo;
}

// Role and Permission types
export interface Role {
  id: string;
  name: string;
  description: string;
  permissions: string[];
}

// API Response types
export interface ApiError {
  error: string;
  message?: string;
}

export interface ApiSuccess<T = any> {
  success: true;
  data?: T;
  message?: string;
}
