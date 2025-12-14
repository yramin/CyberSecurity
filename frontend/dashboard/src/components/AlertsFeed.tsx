import {
  Box,
  Button,
  Chip,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import { useEffect, useState } from 'react';
import { alertsApi } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import type { Alert } from '../types';

const severityColors: Record<string, 'error' | 'warning' | 'info' | 'success'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'info',
};

export default function AlertsFeed() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const { lastMessage } = useWebSocket();

  useEffect(() => {
    loadAlerts();
  }, []);

  useEffect(() => {
    if (lastMessage?.type === 'alert_created' || lastMessage?.type === 'alert_acknowledged') {
      loadAlerts();
    }
  }, [lastMessage]);

  const loadAlerts = async () => {
    try {
      const data = await alertsApi.getAll(0, 100);
      setAlerts(data);
    } catch (error) {
      console.error('Failed to load alerts:', error);
    }
  };

  const handleAcknowledge = async (id: string) => {
    try {
      await alertsApi.acknowledge(id, true);
      loadAlerts();
    } catch (error) {
      console.error('Failed to acknowledge alert:', error);
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h5" gutterBottom>
        Security Alerts
      </Typography>
      <Paper>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>ID</TableCell>
              <TableCell>Type</TableCell>
              <TableCell>Severity</TableCell>
              <TableCell>Message</TableCell>
              <TableCell>Source</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Created</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {alerts.map((alert) => (
              <TableRow key={alert.id}>
                <TableCell>{alert.id.substring(0, 8)}...</TableCell>
                <TableCell>{alert.type}</TableCell>
                <TableCell>
                  <Chip
                    label={alert.severity}
                    color={severityColors[alert.severity] || 'default'}
                    size="small"
                  />
                </TableCell>
                <TableCell>{alert.message}</TableCell>
                <TableCell>{alert.source || 'N/A'}</TableCell>
                <TableCell>
                  {alert.acknowledged ? (
                    <Chip label="Acknowledged" color="success" size="small" />
                  ) : (
                    <Chip label="New" color="warning" size="small" />
                  )}
                </TableCell>
                <TableCell>{new Date(alert.created_at).toLocaleString()}</TableCell>
                <TableCell>
                  {!alert.acknowledged && (
                    <Button
                      size="small"
                      variant="outlined"
                      onClick={() => handleAcknowledge(alert.id)}
                    >
                      Acknowledge
                    </Button>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Paper>
    </Box>
  );
}

