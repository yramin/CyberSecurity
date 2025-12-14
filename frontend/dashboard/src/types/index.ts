export interface Incident {
  id: string;
  title: string;
  description?: string;
  severity: string;
  status: string;
  incident_data?: Record<string, any>;
  remediation_plan?: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface Alert {
  id: string;
  type: string;
  severity: string;
  message: string;
  source?: string;
  alert_data?: Record<string, any>;
  acknowledged: boolean;
  resolved: boolean;
  created_at: string;
  updated_at: string;
}

export interface Vulnerability {
  id: string;
  scanner: string;
  vulnerability_id?: string;
  package?: string;
  severity?: string;
  title?: string;
  description?: string;
  cvss_score?: number;
  vulnerability_data?: Record<string, any>;
  resolved: boolean;
  created_at: string;
  updated_at: string;
}

export interface ComplianceReport {
  id: string;
  framework: string;
  compliance_score?: number;
  report_data?: Record<string, any>;
  gaps?: Array<Record<string, any>>;
  recommendations?: Array<Record<string, any>>;
  created_at: string;
}

export interface WebSocketMessage {
  type: string;
  data: Record<string, any>;
  timestamp: string;
}

