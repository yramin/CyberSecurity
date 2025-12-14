import axios from 'axios';
import type { Alert, ComplianceReport, Incident, Vulnerability } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  auth: {
    username: 'admin',
    password: 'admin123',
  },
});

export const incidentsApi = {
  getAll: async (skip = 0, limit = 100, severity?: string): Promise<Incident[]> => {
    const params: any = { skip, limit };
    if (severity) params.severity = severity;
    const response = await api.get('/api/v1/incidents', { params });
    return response.data;
  },
  getById: async (id: string): Promise<Incident> => {
    const response = await api.get(`/api/v1/incidents/${id}`);
    return response.data;
  },
  create: async (incident: { title: string; description: string; severity?: string; incident_data?: Record<string, any> }): Promise<Incident> => {
    const response = await api.post('/api/v1/incidents', incident);
    return response.data;
  },
};

export const alertsApi = {
  getAll: async (skip = 0, limit = 100, severity?: string, acknowledged?: boolean): Promise<Alert[]> => {
    const params: any = { skip, limit };
    if (severity) params.severity = severity;
    if (acknowledged !== undefined) params.acknowledged = acknowledged;
    const response = await api.get('/api/v1/alerts', { params });
    return response.data;
  },
  acknowledge: async (id: string, acknowledged = true): Promise<Alert> => {
    const response = await api.post(`/api/v1/alerts/${id}/acknowledge`, { acknowledged });
    return response.data;
  },
};

export const vulnerabilitiesApi = {
  getAll: async (skip = 0, limit = 100, severity?: string, resolved?: boolean): Promise<Vulnerability[]> => {
    const params: any = { skip, limit };
    if (severity) params.severity = severity;
    if (resolved !== undefined) params.resolved = resolved;
    const response = await api.get('/api/v1/vulnerabilities', { params });
    return response.data;
  },
};

export const complianceApi = {
  getAll: async (framework?: string, skip = 0, limit = 100): Promise<ComplianceReport[]> => {
    const params: any = { skip, limit };
    if (framework) params.framework = framework;
    const response = await api.get('/api/v1/compliance', { params });
    return response.data;
  },
};

export const agentsApi = {
  trigger: async (agentName: string, task: string, parameters?: Record<string, any>) => {
    const response = await api.post('/api/v1/agents/trigger', {
      agent_name: agentName,
      task,
      parameters: parameters || {},
    });
    return response.data;
  },
};

