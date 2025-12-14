import { Box, Paper, Typography, LinearProgress, Grid, Card, CardContent } from '@mui/material';
import { useEffect, useState } from 'react';
import { complianceApi } from '../services/api';
import type { ComplianceReport } from '../types';

export default function Compliance() {
  const [reports, setReports] = useState<ComplianceReport[]>([]);

  useEffect(() => {
    loadReports();
  }, []);

  const loadReports = async () => {
    try {
      const data = await complianceApi.getAll();
      setReports(data);
    } catch (error) {
      console.error('Failed to load compliance reports:', error);
    }
  };

  const getScoreColor = (score?: number) => {
    if (!score) return 'inherit';
    if (score >= 0.8) return 'success';
    if (score >= 0.6) return 'warning';
    return 'error';
  };

  return (
    <Box sx={{ p: 3 }}>
      <Typography variant="h5" gutterBottom>
        Compliance Reports
      </Typography>
      <Grid container spacing={3}>
        {reports.map((report) => (
          <Grid item xs={12} md={6} key={report.id}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  {report.framework}
                </Typography>
                {report.compliance_score !== undefined && (
                  <Box sx={{ mt: 2 }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
                      <Typography variant="body2">Compliance Score</Typography>
                      <Typography
                        variant="body2"
                        color={`${getScoreColor(report.compliance_score)}.main`}
                        fontWeight="bold"
                      >
                        {(report.compliance_score * 100).toFixed(1)}%
                      </Typography>
                    </Box>
                    <LinearProgress
                      variant="determinate"
                      value={report.compliance_score * 100}
                      color={getScoreColor(report.compliance_score) as any}
                    />
                  </Box>
                )}
                {report.gaps && report.gaps.length > 0 && (
                  <Box sx={{ mt: 2 }}>
                    <Typography variant="body2" color="error">
                      {report.gaps.length} compliance gap(s) found
                    </Typography>
                  </Box>
                )}
                <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                  Generated: {new Date(report.created_at).toLocaleString()}
                </Typography>
              </CardContent>
            </Card>
          </Grid>
        ))}
        {reports.length === 0 && (
          <Grid item xs={12}>
            <Paper sx={{ p: 3, textAlign: 'center' }}>
              <Typography variant="body1" color="text.secondary">
                No compliance reports available
              </Typography>
            </Paper>
          </Grid>
        )}
      </Grid>
    </Box>
  );
}

