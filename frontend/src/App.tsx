import { useEffect, useState, useMemo, Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme, CssBaseline, Box, CircularProgress } from '@mui/material';
import { LocalizationProvider } from '@mui/x-date-pickers';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { Provider as ReduxProvider } from 'react-redux';
import { ToastContainer } from 'react-toastify';
import { io, Socket } from 'socket.io-client';
import { registerSW } from 'virtual:pwa-register';
import { I18nextProvider } from 'react-i18next';

// Import custom contexts
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { TenantProvider, useTenant } from './contexts/TenantContext';
import { ThemeProvider as CustomThemeProvider, useTheme } from './contexts/ThemeContext';
import { NotificationProvider } from './contexts/NotificationContext';
import { SocketProvider } from './contexts/SocketContext';
import { PermissionProvider } from './contexts/PermissionContext';

// Import store
import { store } from './store';

// Import i18n configuration
import i18n from './i18n';

// Import components
import ErrorBoundary from './components/common/ErrorBoundary';
import FullScreenLoader from './components/common/FullScreenLoader';
import MainLayout from './layouts/MainLayout';
import AuthLayout from './layouts/AuthLayout';
import TenantSelector from './components/tenant/TenantSelector';
import ProtectedRoute from './components/auth/ProtectedRoute';
import RoleBasedRoute from './components/auth/RoleBasedRoute';
import NotFound from './pages/NotFound';
import Maintenance from './pages/Maintenance';

// Import styles
import 'react-toastify/dist/ReactToastify.css';
import './styles/global.scss';

// Lazy-loaded pages for code splitting
const Dashboard = lazy(() => import('./pages/Dashboard'));
const SecurityEvents = lazy(() => import('./pages/SecurityEvents'));
const Alerts = lazy(() => import('./pages/Alerts'));
const Incidents = lazy(() => import('./pages/Incidents'));
const ThreatIntelligence = lazy(() => import('./pages/ThreatIntelligence'));
const Reports = lazy(() => import('./pages/Reports'));
const Settings = lazy(() => import('./pages/Settings'));
const Login = lazy(() => import('./pages/auth/Login'));
const Register = lazy(() => import('./pages/auth/Register'));
const ForgotPassword = lazy(() => import('./pages/auth/ForgotPassword'));
const ResetPassword = lazy(() => import('./pages/auth/ResetPassword'));
const UserProfile = lazy(() => import('./pages/UserProfile'));
const TenantSettings = lazy(() => import('./pages/admin/TenantSettings'));
const UserManagement = lazy(() => import('./pages/admin/UserManagement'));
const RoleManagement = lazy(() => import('./pages/admin/RoleManagement'));
const AuditLogs = lazy(() => import('./pages/admin/AuditLogs'));
const IntegrationSettings = lazy(() => import('./pages/admin/IntegrationSettings'));
const BillingPortal = lazy(() => import('./pages/admin/BillingPortal'));

// Tool-specific pages
const WazuhDashboard = lazy(() => import('./pages/tools/WazuhDashboard'));
const GraylogConsole = lazy(() => import('./pages/tools/GraylogConsole'));
const TheHiveCases = lazy(() => import('./pages/tools/TheHiveCases'));
const OpenCTIDashboard = lazy(() => import('./pages/tools/OpenCTIDashboard'));
const MISPEvents = lazy(() => import('./pages/tools/MISPEvents'));
const VelociraptorHunts = lazy(() => import('./pages/tools/VelociraptorHunts'));
const MLAnomalyDetection = lazy(() => import('./pages/tools/MLAnomalyDetection'));

// Create query client for React Query
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 1000 * 60 * 5, // 5 minutes
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

// Initialize PWA
const updateSW = registerSW({
  onNeedRefresh() {
    if (confirm('New content available. Reload?')) {
      updateSW(true);
    }
  },
});

/**
 * Main application component
 */
const App = () => {
  return (
    <ErrorBoundary>
      <ReduxProvider store={store}>
        <QueryClientProvider client={queryClient}>
          <I18nextProvider i18n={i18n}>
            <CustomThemeProvider>
              <AuthProvider>
                <TenantProvider>
                  <NotificationProvider>
                    <SocketConnectionManager>
                      <AppContent />
                    </SocketConnectionManager>
                  </NotificationProvider>
                </TenantProvider>
              </AuthProvider>
            </CustomThemeProvider>
          </I18nextProvider>
          {process.env.NODE_ENV === 'development' && <ReactQueryDevtools initialIsOpen={false} />}
        </QueryClientProvider>
      </ReduxProvider>
      <ToastContainer
        position="top-right"
        autoClose={5000}
        hideProgressBar={false}
        newestOnTop
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
        theme="colored"
      />
    </ErrorBoundary>
  );
};

/**
 * Socket connection manager component
 */
const SocketConnectionManager = ({ children }: { children: React.ReactNode }) => {
  const { isAuthenticated, token } = useAuth();
  const { currentTenant } = useTenant();
  const [socket, setSocket] = useState<Socket | null>(null);

  useEffect(() => {
    if (isAuthenticated && currentTenant) {
      // Initialize socket connection with auth token and tenant info
      const newSocket = io(import.meta.env.VITE_API_URL, {
        auth: {
          token,
          tenantId: currentTenant.id,
        },
        transports: ['websocket'],
        reconnection: true,
        reconnectionAttempts: Infinity,
        reconnectionDelay: 1000,
      });

      setSocket(newSocket);

      return () => {
        newSocket.disconnect();
      };
    }
    return undefined;
  }, [isAuthenticated, token, currentTenant]);

  return <SocketProvider socket={socket}>{children}</SocketProvider>;
};

/**
 * Main application content with theming and routing
 */
const AppContent = () => {
  const { theme, mode } = useTheme();
  const { isAuthenticated, isLoading: authLoading, user } = useAuth();
  const { currentTenant, tenants, isLoading: tenantLoading } = useTenant();

  // Create MUI theme based on current theme settings
  const muiTheme = useMemo(
    () =>
      createTheme({
        palette: {
          mode: mode,
          primary: {
            main: theme.primaryColor,
          },
          secondary: {
            main: theme.secondaryColor,
          },
          background: {
            default: mode === 'dark' ? '#121212' : '#f5f5f5',
            paper: mode === 'dark' ? '#1e1e1e' : '#ffffff',
          },
          error: {
            main: '#f44336',
          },
          warning: {
            main: '#ff9800',
          },
          info: {
            main: '#2196f3',
          },
          success: {
            main: '#4caf50',
          },
        },
        typography: {
          fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
        },
        shape: {
          borderRadius: 8,
        },
        components: {
          MuiCssBaseline: {
            styleOverrides: {
              body: {
                scrollbarWidth: 'thin',
                '&::-webkit-scrollbar': {
                  width: '8px',
                  height: '8px',
                },
                '&::-webkit-scrollbar-track': {
                  background: mode === 'dark' ? '#1e1e1e' : '#f1f1f1',
                },
                '&::-webkit-scrollbar-thumb': {
                  background: mode === 'dark' ? '#555' : '#888',
                  borderRadius: '4px',
                },
                '&::-webkit-scrollbar-thumb:hover': {
                  background: mode === 'dark' ? '#777' : '#555',
                },
              },
            },
          },
          MuiButton: {
            styleOverrides: {
              root: {
                textTransform: 'none',
              },
            },
          },
          MuiAppBar: {
            styleOverrides: {
              root: {
                boxShadow: mode === 'dark' ? '0 1px 3px rgba(0,0,0,0.5)' : '0 1px 3px rgba(0,0,0,0.1)',
              },
            },
          },
          MuiCard: {
            styleOverrides: {
              root: {
                boxShadow: mode === 'dark' ? '0 4px 8px rgba(0,0,0,0.5)' : '0 2px 8px rgba(0,0,0,0.08)',
              },
            },
          },
        },
      }),
    [mode, theme]
  );

  // Show loading screen while authentication and tenant data are loading
  if (authLoading || (isAuthenticated && tenantLoading)) {
    return <FullScreenLoader />;
  }

  // Show tenant selector if authenticated but no tenant is selected
  if (isAuthenticated && tenants.length > 0 && !currentTenant) {
    return (
      <ThemeProvider theme={muiTheme}>
        <CssBaseline />
        <LocalizationProvider dateAdapter={AdapterDayjs}>
          <Box
            sx={{
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              minHeight: '100vh',
              bgcolor: 'background.default',
            }}
          >
            <TenantSelector tenants={tenants} />
          </Box>
        </LocalizationProvider>
      </ThemeProvider>
    );
  }

  return (
    <ThemeProvider theme={muiTheme}>
      <CssBaseline />
      <LocalizationProvider dateAdapter={AdapterDayjs}>
        <PermissionProvider>
          <BrowserRouter>
            <Suspense fallback={<FullScreenLoader />}>
              <Routes>
                {/* Public routes */}
                <Route element={<AuthLayout />}>
                  <Route path="/login" element={<Login />} />
                  <Route path="/register" element={<Register />} />
                  <Route path="/forgot-password" element={<ForgotPassword />} />
                  <Route path="/reset-password" element={<ResetPassword />} />
                  <Route path="/maintenance" element={<Maintenance />} />
                </Route>

                {/* Protected routes */}
                <Route
                  element={
                    <ProtectedRoute>
                      <MainLayout />
                    </ProtectedRoute>
                  }
                >
                  {/* Dashboard */}
                  <Route path="/" element={<Navigate to="/dashboard" replace />} />
                  <Route path="/dashboard" element={<Dashboard />} />

                  {/* Security Monitoring */}
                  <Route path="/security-events" element={<SecurityEvents />} />
                  <Route path="/alerts" element={<Alerts />} />
                  <Route path="/incidents" element={<Incidents />} />
                  <Route path="/threat-intelligence" element={<ThreatIntelligence />} />
                  <Route path="/reports" element={<Reports />} />

                  {/* Tool-specific routes */}
                  <Route path="/tools/wazuh" element={<WazuhDashboard />} />
                  <Route path="/tools/graylog" element={<GraylogConsole />} />
                  <Route path="/tools/thehive" element={<TheHiveCases />} />
                  <Route path="/tools/opencti" element={<OpenCTIDashboard />} />
                  <Route path="/tools/misp" element={<MISPEvents />} />
                  <Route path="/tools/velociraptor" element={<VelociraptorHunts />} />
                  <Route path="/tools/ml-anomaly-detection" element={<MLAnomalyDetection />} />

                  {/* User settings */}
                  <Route path="/profile" element={<UserProfile />} />
                  <Route path="/settings" element={<Settings />} />

                  {/* Admin routes */}
                  <Route
                    path="/admin/tenants"
                    element={
                      <RoleBasedRoute requiredRole="admin">
                        <TenantSettings />
                      </RoleBasedRoute>
                    }
                  />
                  <Route
                    path="/admin/users"
                    element={
                      <RoleBasedRoute requiredRole="admin">
                        <UserManagement />
                      </RoleBasedRoute>
                    }
                  />
                  <Route
                    path="/admin/roles"
                    element={
                      <RoleBasedRoute requiredRole="admin">
                        <RoleManagement />
                      </RoleBasedRoute>
                    }
                  />
                  <Route
                    path="/admin/audit-logs"
                    element={
                      <RoleBasedRoute requiredRole="admin">
                        <AuditLogs />
                      </RoleBasedRoute>
                    }
                  />
                  <Route
                    path="/admin/integrations"
                    element={
                      <RoleBasedRoute requiredRole="admin">
                        <IntegrationSettings />
                      </RoleBasedRoute>
                    }
                  />
                  <Route
                    path="/admin/billing"
                    element={
                      <RoleBasedRoute requiredRole="admin">
                        <BillingPortal />
                      </RoleBasedRoute>
                    }
                  />
                </Route>

                {/* 404 page */}
                <Route path="*" element={<NotFound />} />
              </Routes>
            </Suspense>
          </BrowserRouter>
        </PermissionProvider>
      </LocalizationProvider>
    </ThemeProvider>
  );
};

export default App;
