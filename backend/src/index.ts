/**
 * AfCyber SIEM - Multi-Tenant SaaS Platform
 * Main API Server Entry Point
 * 
 * This file initializes the Express application, sets up middleware,
 * establishes database connections, configures authentication,
 * registers API routes, and starts the server.
 * 
 * @copyright AfCyber Labs 2025
 * @license Apache-2.0
 */

import 'reflect-metadata';
import 'express-async-errors';
import * as dotenv from 'dotenv';
import express, { Request, Response, NextFunction, Application } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import session from 'express-session';
import RedisStore from 'connect-redis';
import { createClient } from 'ioredis';
import { expressjwt as jwt } from 'express-jwt';
import passport from 'passport';
import { DataSource } from 'typeorm';
import { Client } from '@elastic/elasticsearch';
import { Kafka } from 'kafkajs';
import * as Sentry from '@sentry/node';
import swaggerJsdoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';
import { pino } from 'pino';
import pinoHttp from 'pino-http';
import * as http from 'http';
import * as https from 'https';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as cluster from 'cluster';
import { v4 as uuidv4 } from 'uuid';

// Load environment variables
dotenv.config();

// Initialize logger
const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: process.env.NODE_ENV === 'development' 
    ? { target: 'pino-pretty' } 
    : undefined,
  redact: ['req.headers.authorization', 'req.headers.cookie', 'req.body.password'],
});

// Initialize metrics and monitoring
import { initializeMonitoring } from './monitoring';
import { setupOpenTelemetry } from './telemetry';

// Import configuration
import { config } from './config';

// Import database connections
import { initializeDatabase } from './database';
import { initializeRedis } from './cache';

// Import authentication strategies
import { configurePassport } from './auth/passport';
import { jwtStrategy } from './auth/strategies/jwt.strategy';
import { localStrategy } from './auth/strategies/local.strategy';
import { samlStrategy } from './auth/strategies/saml.strategy';

// Import multi-tenant middleware
import { tenantMiddleware } from './middleware/tenant.middleware';
import { tenantContext } from './middleware/tenant-context.middleware';

// Import security middleware
import { csrfProtection } from './middleware/csrf.middleware';
import { securityHeaders } from './middleware/security-headers.middleware';

// Import error handling
import { errorHandler } from './middleware/error-handler.middleware';
import { notFoundHandler } from './middleware/not-found.middleware';

// Import API routes
import { apiRouter } from './routes';
import { authRouter } from './routes/auth.routes';
import { tenantsRouter } from './routes/tenants.routes';
import { usersRouter } from './routes/users.routes';
import { alertsRouter } from './routes/alerts.routes';
import { incidentsRouter } from './routes/incidents.routes';
import { dashboardsRouter } from './routes/dashboards.routes';
import { reportsRouter } from './routes/reports.routes';
import { settingsRouter } from './routes/settings.routes';
import { integrationsRouter } from './routes/integrations.routes';
import { mlRouter } from './routes/ml.routes';

// Import service integrations
import { initializeWazuh } from './integrations/wazuh';
import { initializeGraylog } from './integrations/graylog';
import { initializeTheHive } from './integrations/thehive';
import { initializeOpenCTI } from './integrations/opencti';
import { initializeMISP } from './integrations/misp';
import { initializeVelociraptor } from './integrations/velociraptor';
import { initializeKafka } from './integrations/kafka';
import { initializeMLServices } from './integrations/ml-services';

// Import types
import { AppDataSource } from './database/data-source';
import { TenantInfo } from './types/tenant.types';

// Declare global augmentation for Express Request
declare global {
  namespace Express {
    interface Request {
      id: string;
      tenant?: TenantInfo;
      user?: any;
      redis?: ReturnType<typeof createClient>;
    }
  }
}

// Initialize Sentry for error tracking in production
if (process.env.NODE_ENV === 'production' && config.sentry.dsn) {
  Sentry.init({
    dsn: config.sentry.dsn,
    environment: process.env.NODE_ENV,
    release: process.env.npm_package_version,
    integrations: [
      new Sentry.Integrations.Http({ tracing: true }),
      new Sentry.Integrations.Express({ app: express() }),
    ],
    tracesSampleRate: 0.2,
  });
}

/**
 * Initialize the Express application with all middleware and configurations
 */
async function initializeApp(): Promise<Application> {
  try {
    logger.info('Initializing AfCyber SIEM SaaS API server...');
    
    // Initialize Express app
    const app: Application = express();
    
    // Setup OpenTelemetry for distributed tracing
    if (config.telemetry.enabled) {
      await setupOpenTelemetry();
    }
    
    // Initialize monitoring
    initializeMonitoring(app);
    
    // Request ID middleware - assign unique ID to each request for tracing
    app.use((req: Request, res: Response, next: NextFunction) => {
      req.id = uuidv4();
      res.setHeader('X-Request-ID', req.id);
      next();
    });
    
    // Sentry request handler
    if (process.env.NODE_ENV === 'production' && config.sentry.dsn) {
      app.use(Sentry.Handlers.requestHandler());
      app.use(Sentry.Handlers.tracingHandler());
    }
    
    // Basic middleware
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    app.use(compression());
    
    // Security middleware
    app.use(helmet({
      contentSecurityPolicy: process.env.NODE_ENV === 'production' ? undefined : false,
    }));
    
    app.use(cors({
      origin: config.cors.origins,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-Tenant-ID'],
      credentials: true,
      maxAge: 86400, // 1 day
    }));
    
    // Apply security headers
    app.use(securityHeaders);
    
    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: config.rateLimit.max, // limit each IP to 100 requests per windowMs
      standardHeaders: true,
      legacyHeaders: false,
      message: 'Too many requests from this IP, please try again after 15 minutes',
      skip: (req) => {
        // Skip rate limiting for internal health checks
        return req.path === '/health' || req.path === '/readiness';
      }
    });
    app.use(limiter);
    
    // Initialize database connections
    logger.info('Initializing database connections...');
    const dataSource = await initializeDatabase();
    
    // Initialize Redis
    logger.info('Initializing Redis connection...');
    const redisClient = await initializeRedis();
    
    // Session management with Redis
    app.use(session({
      store: new RedisStore({ client: redisClient }),
      secret: config.session.secret,
      resave: false,
      saveUninitialized: false,
      name: 'afcyber.sid',
      cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 1 day
        sameSite: 'lax',
      },
    }));
    
    // Initialize passport for authentication
    app.use(passport.initialize());
    app.use(passport.session());
    configurePassport(passport);
    passport.use(jwtStrategy);
    passport.use(localStrategy);
    
    // Setup SAML authentication if enabled
    if (config.auth.saml.enabled) {
      passport.use(samlStrategy);
    }
    
    // JWT authentication middleware for protected routes
    app.use(
      jwt({
        secret: config.jwt.secret,
        algorithms: ['HS256'],
        credentialsRequired: false,
        getToken: (req) => {
          if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
            return req.headers.authorization.split(' ')[1];
          }
          return null;
        }
      })
    );
    
    // Setup request logging with pino
    app.use(pinoHttp({
      logger,
      autoLogging: {
        ignore: (req) => req.url === '/health' || req.url === '/readiness'
      },
      customProps: (req, res) => {
        return {
          requestId: req.id,
          tenant: req.tenant?.id || 'system',
          userId: req.user?.id || 'anonymous',
        };
      }
    }));
    
    // Initialize service integrations
    logger.info('Initializing service integrations...');
    const wazuh = await initializeWazuh();
    const graylog = await initializeGraylog();
    const theHive = await initializeTheHive();
    const openCTI = await initializeOpenCTI();
    const misp = await initializeMISP();
    const velociraptor = await initializeVelociraptor();
    
    // Initialize Kafka for event streaming
    logger.info('Initializing Kafka connection...');
    const kafka = await initializeKafka();
    
    // Initialize ML services
    logger.info('Initializing ML services...');
    const mlServices = await initializeMLServices();
    
    // Make services available to request handlers
    app.use((req: Request, res: Response, next: NextFunction) => {
      req.app.locals.dataSource = dataSource;
      req.app.locals.redis = redisClient;
      req.app.locals.wazuh = wazuh;
      req.app.locals.graylog = graylog;
      req.app.locals.theHive = theHive;
      req.app.locals.openCTI = openCTI;
      req.app.locals.misp = misp;
      req.app.locals.velociraptor = velociraptor;
      req.app.locals.kafka = kafka;
      req.app.locals.mlServices = mlServices;
      next();
    });
    
    // Multi-tenant middleware - extract tenant information from request
    app.use(tenantMiddleware);
    app.use(tenantContext);
    
    // CSRF protection for non-GET requests
    if (config.security.csrf.enabled) {
      app.use(csrfProtection);
    }
    
    // API documentation setup
    const swaggerOptions = {
      definition: {
        openapi: '3.0.0',
        info: {
          title: 'AfCyber SIEM SaaS API',
          version: process.env.npm_package_version || '1.0.0',
          description: 'API documentation for the AfCyber SIEM Multi-Tenant SaaS Platform',
          license: {
            name: 'Apache 2.0',
            url: 'https://www.apache.org/licenses/LICENSE-2.0.html',
          },
          contact: {
            name: 'AfCyber Labs',
            url: 'https://afcyber.example.com',
            email: 'support@afcyber.example.com',
          },
        },
        servers: [
          {
            url: config.api.baseUrl,
            description: 'Production API Server',
          },
          {
            url: 'http://localhost:3000',
            description: 'Development API Server',
          },
        ],
        components: {
          securitySchemes: {
            bearerAuth: {
              type: 'http',
              scheme: 'bearer',
              bearerFormat: 'JWT',
            },
            ApiKeyAuth: {
              type: 'apiKey',
              in: 'header',
              name: 'X-API-KEY',
            },
          },
        },
        security: [
          {
            bearerAuth: [],
          },
        ],
      },
      apis: ['./src/routes/*.ts', './src/controllers/*.ts', './src/models/*.ts'],
    };
    
    const swaggerSpec = swaggerJsdoc(swaggerOptions);
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
    app.get('/api-docs.json', (req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.send(swaggerSpec);
    });
    
    // Health check endpoints
    app.get('/health', (req, res) => {
      res.status(200).json({ status: 'UP', timestamp: new Date().toISOString() });
    });
    
    app.get('/readiness', async (req, res) => {
      try {
        const dbStatus = dataSource.isInitialized;
        const redisStatus = redisClient.status === 'ready';
        
        if (dbStatus && redisStatus) {
          res.status(200).json({
            status: 'READY',
            timestamp: new Date().toISOString(),
            services: {
              database: 'UP',
              redis: 'UP',
              wazuh: wazuh ? 'UP' : 'DOWN',
              graylog: graylog ? 'UP' : 'DOWN',
              theHive: theHive ? 'UP' : 'DOWN',
              openCTI: openCTI ? 'UP' : 'DOWN',
              misp: misp ? 'UP' : 'DOWN',
              velociraptor: velociraptor ? 'UP' : 'DOWN',
              kafka: kafka ? 'UP' : 'DOWN',
              mlServices: mlServices ? 'UP' : 'DOWN',
            },
          });
        } else {
          res.status(503).json({
            status: 'NOT_READY',
            timestamp: new Date().toISOString(),
            services: {
              database: dbStatus ? 'UP' : 'DOWN',
              redis: redisStatus ? 'UP' : 'DOWN',
            },
          });
        }
      } catch (error) {
        res.status(500).json({
          status: 'ERROR',
          timestamp: new Date().toISOString(),
          error: error.message,
        });
      }
    });
    
    // Register API routes
    app.use('/api/v1/auth', authRouter);
    app.use('/api/v1/tenants', tenantsRouter);
    app.use('/api/v1/users', usersRouter);
    app.use('/api/v1/alerts', alertsRouter);
    app.use('/api/v1/incidents', incidentsRouter);
    app.use('/api/v1/dashboards', dashboardsRouter);
    app.use('/api/v1/reports', reportsRouter);
    app.use('/api/v1/settings', settingsRouter);
    app.use('/api/v1/integrations', integrationsRouter);
    app.use('/api/v1/ml', mlRouter);
    app.use('/api/v1', apiRouter);
    
    // 404 handler
    app.use(notFoundHandler);
    
    // Error handling middleware
    if (process.env.NODE_ENV === 'production' && config.sentry.dsn) {
      app.use(Sentry.Handlers.errorHandler());
    }
    app.use(errorHandler);
    
    logger.info('AfCyber SIEM SaaS API server initialization complete');
    return app;
  } catch (error) {
    logger.error({ err: error }, 'Failed to initialize application');
    throw error;
  }
}

/**
 * Start the server and listen for requests
 */
async function startServer() {
  try {
    const app = await initializeApp();
    let server: http.Server | https.Server;
    
    // Create HTTP or HTTPS server based on configuration
    if (config.server.ssl.enabled) {
      const sslOptions = {
        key: fs.readFileSync(config.server.ssl.keyPath),
        cert: fs.readFileSync(config.server.ssl.certPath),
      };
      server = https.createServer(sslOptions, app);
    } else {
      server = http.createServer(app);
    }
    
    // Start server
    server.listen(config.server.port, () => {
      logger.info(`AfCyber SIEM SaaS API server running on port ${config.server.port} in ${process.env.NODE_ENV} mode`);
      logger.info(`API documentation available at ${config.server.ssl.enabled ? 'https' : 'http'}://localhost:${config.server.port}/api-docs`);
    });
    
    // Handle graceful shutdown
    const gracefulShutdown = async (signal: string) => {
      logger.info(`${signal} received, starting graceful shutdown...`);
      
      // Close server connections
      server.close(async () => {
        logger.info('HTTP server closed');
        
        try {
          // Close database connections
          if (AppDataSource.isInitialized) {
            await AppDataSource.destroy();
            logger.info('Database connections closed');
          }
          
          // Close Redis connections
          if (app.locals.redis) {
            await app.locals.redis.quit();
            logger.info('Redis connections closed');
          }
          
          // Close Kafka connections
          if (app.locals.kafka) {
            await app.locals.kafka.disconnect();
            logger.info('Kafka connections closed');
          }
          
          logger.info('Graceful shutdown completed');
          process.exit(0);
        } catch (error) {
          logger.error({ err: error }, 'Error during graceful shutdown');
          process.exit(1);
        }
      });
      
      // Force shutdown after timeout
      setTimeout(() => {
        logger.error('Graceful shutdown timed out, forcing exit');
        process.exit(1);
      }, 30000); // 30 seconds
    };
    
    // Register shutdown handlers
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    
    // Handle uncaught exceptions and unhandled rejections
    process.on('uncaughtException', (error) => {
      logger.error({ err: error }, 'Uncaught exception');
      if (process.env.NODE_ENV === 'production') {
        Sentry.captureException(error);
      }
      // In production, we should gracefully shutdown on uncaught exceptions
      if (process.env.NODE_ENV === 'production') {
        gracefulShutdown('UNCAUGHT_EXCEPTION');
      }
    });
    
    process.on('unhandledRejection', (reason, promise) => {
      logger.error({ reason }, 'Unhandled promise rejection');
      if (process.env.NODE_ENV === 'production') {
        Sentry.captureException(reason);
      }
    });
    
    return server;
  } catch (error) {
    logger.error({ err: error }, 'Failed to start server');
    if (process.env.NODE_ENV === 'production' && config.sentry.dsn) {
      Sentry.captureException(error);
      await Sentry.close(2000);
    }
    process.exit(1);
  }
}

// Start the server in cluster mode if enabled, otherwise start normally
if (config.server.cluster.enabled && cluster.isPrimary) {
  logger.info(`Primary ${process.pid} is running`);
  
  // Fork workers based on CPU count
  const numCPUs = config.server.cluster.workers || os.cpus().length;
  for (let i = 0; i < numCPUs; i++) {
    cluster.fork();
  }
  
  cluster.on('exit', (worker, code, signal) => {
    logger.warn(`Worker ${worker.process.pid} died with code ${code} and signal ${signal}`);
    logger.info('Starting a new worker');
    cluster.fork();
  });
} else {
  startServer()
    .then(() => {
      if (cluster.isWorker) {
        logger.info(`Worker ${process.pid} started`);
      }
    })
    .catch((error) => {
      logger.error({ err: error }, 'Server failed to start');
      process.exit(1);
    });
}

// Export for testing purposes
export { initializeApp };
