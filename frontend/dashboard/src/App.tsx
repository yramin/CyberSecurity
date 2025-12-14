import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { AppBar, Box, Container, Tab, Tabs, Toolbar, Typography } from '@mui/material';
import { useState } from 'react';
import Dashboard from './components/Dashboard';
import AlertsFeed from './components/AlertsFeed';
import Incidents from './components/Incidents';
import Compliance from './components/Compliance';

const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',
    },
    secondary: {
      main: '#dc004e',
    },
  },
});

function App() {
  const [currentTab, setCurrentTab] = useState(0);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <Box sx={{ flexGrow: 1 }}>
          <AppBar position="static">
            <Toolbar>
              <Typography variant="h6" component="div" sx={{ flexGrow: 1 }}>
                Cyber Security AI Agent System
              </Typography>
            </Toolbar>
          </AppBar>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <Tabs value={currentTab} onChange={(_, v) => setCurrentTab(v)}>
              <Tab label="Dashboard" component={Link} to="/" />
              <Tab label="Alerts" component={Link} to="/alerts" />
              <Tab label="Incidents" component={Link} to="/incidents" />
              <Tab label="Compliance" component={Link} to="/compliance" />
            </Tabs>
          </Box>
          <Container maxWidth="xl" sx={{ mt: 3 }}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/alerts" element={<AlertsFeed />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/compliance" element={<Compliance />} />
            </Routes>
          </Container>
        </Box>
      </Router>
    </ThemeProvider>
  );
}

export default App;

