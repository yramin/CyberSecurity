import { Box, Grid, Paper, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { alertsApi, incidentsApi, vulnerabilitiesApi } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import type { Alert, Incident, Vulnerability } from '../types';

const COLORS = ['#0088FE', '#00C49F', '#FFBB28', '#FF8042', '#8884d8'];

export default function Dashboard() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const { lastMessage, connected } = useWebSocket();

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    if (lastMessage) {
      // Handle real-time updates
      if (lastMessage.type === 'alert_created' || lastMessage.type === 'alert_acknowledged') {
        loadAlerts();
      } else if (lastMessage.type === 'incident_created') {
        loadIncidents();
      }
    }
  }, [lastMessage]);

  const loadData = async () => {
    try {
      const [alertsData, incidentsData, vulnsData] = await Promise.all([
        alertsApi.getAll(0, 100),
        incidentsApi.getAll(0, 100),
        vulnerabilitiesApi.getAll(0, 100),
      ]);
      setAlerts(alertsData);
      setIncidents(incidentsData);
      setVulnerabilities(vulnsData);
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    }
  };

  const alertsBySeverity = alerts.reduce((acc, alert) => {
    acc[alert.severity] = (acc[alert.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const incidentsByStatus = incidents.reduce((acc, incident) => {
    acc[incident.status] = (acc[incident.status] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const vulnsBySeverity = vulnerabilities.reduce((acc, vuln) => {
    const severity = vuln.severity || 'unknown';
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const alertsChartData = Object.entries(alertsBySeverity).map(([name, value]) => ({ name, value }));
  const incidentsChartData = Object.entries(incidentsByStatus).map(([name, value]) => ({ name, value }));
  const vulnsChartData = Object.entries(vulnsBySeverity).map(([name, value]) => ({ name, value }));

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h4" gutterBottom>
        Security Dashboard
      </Typography>
      <Box sx={{ mb: 2 }}>
        <Typography variant="body2" color={connected ? 'success.main' : 'error.main'}>
          WebSocket: {connected ? 'Connected' : 'Disconnected'}
        </Typography>
      </Box>

      <Grid container spacing={3}>
        {/* Summary Cards */}
        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 2, textAlign: 'center' }}>
            <Typography variant="h6">Total Alerts</Typography>
            <Typography variant="h4">{alerts.length}</Typography>
          </Paper>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 2, textAlign: 'center' }}>
            <Typography variant="h6">Active Incidents</Typography>
            <Typography variant="h4">{incidents.filter(i => i.status === 'open').length}</Typography>
          </Paper>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 2, textAlign: 'center' }}>
            <Typography variant="h6">Vulnerabilities</Typography>
            <Typography variant="h4">{vulnerabilities.length}</Typography>
          </Paper>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Paper sx={{ p: 2, textAlign: 'center' }}>
            <Typography variant="h6">Critical Alerts</Typography>
            <Typography variant="h4" color="error">
              {alerts.filter(a => a.severity === 'critical').length}
            </Typography>
          </Paper>
        </Grid>

        {/* Charts */}
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Alerts by Severity
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={alertsChartData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {alertsChartData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Incidents by Status
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={incidentsChartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="value" fill="#8884d8" />
              </BarChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 2 }}>
            <Typography variant="h6" gutterBottom>
              Vulnerabilities by Severity
            </Typography>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={vulnsChartData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="value" fill="#82ca9d" />
              </BarChart>
            </ResponsiveContainer>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}

