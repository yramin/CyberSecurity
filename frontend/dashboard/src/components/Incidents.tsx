import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Dialog,
  DialogContent,
  DialogTitle,
  Grid,
  TextField,
  Typography,
} from '@mui/material';
import { useState, useEffect } from 'react';
import { incidentsApi } from '../services/api';
import { useWebSocket } from '../hooks/useWebSocket';
import type { Incident } from '../types';

const severityColors: Record<string, 'error' | 'warning' | 'info'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'info',
};

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [open, setOpen] = useState(false);
  const [createOpen, setCreateOpen] = useState(false);
  const [newIncident, setNewIncident] = useState({ title: '', description: '', severity: 'medium' });
  const { lastMessage } = useWebSocket();

  useEffect(() => {
    loadIncidents();
  }, []);

  useEffect(() => {
    if (lastMessage?.type === 'incident_created') {
      loadIncidents();
    }
  }, [lastMessage]);

  const loadIncidents = async () => {
    try {
      const data = await incidentsApi.getAll(0, 100);
      setIncidents(data);
    } catch (error) {
      console.error('Failed to load incidents:', error);
    }
  };

  const handleCreate = async () => {
    try {
      await incidentsApi.create(newIncident);
      setCreateOpen(false);
      setNewIncident({ title: '', description: '', severity: 'medium' });
      loadIncidents();
    } catch (error) {
      console.error('Failed to create incident:', error);
    }
  };

  return (
    <Box sx={{ p: 3 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h5">Security Incidents</Typography>
        <Button variant="contained" onClick={() => setCreateOpen(true)}>
          Create Incident
        </Button>
      </Box>

      <Grid container spacing={2}>
        {incidents.map((incident) => (
          <Grid item xs={12} md={6} key={incident.id}>
            <Card>
              <CardContent>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                  <Typography variant="h6">{incident.title}</Typography>
                  <Chip
                    label={incident.severity}
                    color={severityColors[incident.severity] || 'default'}
                    size="small"
                  />
                </Box>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  {incident.description}
                </Typography>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Typography variant="caption">
                    Status: {incident.status} | Created: {new Date(incident.created_at).toLocaleString()}
                  </Typography>
                  <Button size="small" onClick={() => { setSelectedIncident(incident); setOpen(true); }}>
                    View Details
                  </Button>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>{selectedIncident?.title}</DialogTitle>
        <DialogContent>
          {selectedIncident && (
            <Box>
              <Typography variant="body1" sx={{ mb: 2 }}>
                {selectedIncident.description}
              </Typography>
              {selectedIncident.remediation_plan && (
                <Box sx={{ mt: 2 }}>
                  <Typography variant="h6" gutterBottom>
                    Remediation Plan
                  </Typography>
                  <Typography variant="body2" component="pre" sx={{ whiteSpace: 'pre-wrap' }}>
                    {JSON.stringify(selectedIncident.remediation_plan, null, 2)}
                  </Typography>
                </Box>
              )}
            </Box>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={createOpen} onClose={() => setCreateOpen(false)}>
        <DialogTitle>Create New Incident</DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
            <TextField
              label="Title"
              value={newIncident.title}
              onChange={(e) => setNewIncident({ ...newIncident, title: e.target.value })}
              fullWidth
            />
            <TextField
              label="Description"
              value={newIncident.description}
              onChange={(e) => setNewIncident({ ...newIncident, description: e.target.value })}
              multiline
              rows={4}
              fullWidth
            />
            <TextField
              label="Severity"
              select
              value={newIncident.severity}
              onChange={(e) => setNewIncident({ ...newIncident, severity: e.target.value })}
              SelectProps={{ native: true }}
              fullWidth
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </TextField>
            <Button variant="contained" onClick={handleCreate}>
              Create
            </Button>
          </Box>
        </DialogContent>
      </Dialog>
    </Box>
  );
}

