#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AfCyber SIEM - Time-Series Anomaly Detection Microservice

This module provides a Flask-based API for time-series anomaly detection
using multiple algorithms (Seasonal-Hybrid ESD, Prophet, LSTM) with
multi-tenant isolation, Kafka integration, and Elasticsearch data storage.

Author: AfCyber Labs
License: Apache-2.0
"""

import os
import sys
import json
import time
import uuid
import logging
import threading
import traceback
import pickle
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Union, Optional, Any

# Flask and API dependencies
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
from apscheduler.schedulers.background import BackgroundScheduler
from prometheus_client import Counter, Histogram, Gauge, Summary, generate_latest, REGISTRY

# ML dependencies
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model, save_model
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
from tensorflow.keras.optimizers import Adam
from sklearn.preprocessing import MinMaxScaler, StandardScaler
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score
import fbprophet
from fbprophet import Prophet
from fbprophet.diagnostics import cross_validation, performance_metrics
from statsmodels.tsa.seasonal import seasonal_decompose
import pyod.models.hbos
from scipy import stats

# Kafka integration
from confluent_kafka import Consumer, KafkaError, Producer

# Elasticsearch integration
from elasticsearch import Elasticsearch, helpers

# Redis integration
import redis

# Set TensorFlow log level
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # 0=all, 1=info, 2=warning, 3=error

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(tenant)s] - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

# Create logger
logger = logging.getLogger('anomaly-detection')
logger = logging.LoggerAdapter(logger, {"tenant": "system"})

# Configuration management
class Config:
    """Configuration management for the anomaly detection service"""
    
    def __init__(self):
        # Service configuration
        self.DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
        self.HOST = os.getenv('HOST', '0.0.0.0')
        self.PORT = int(os.getenv('PORT', '5000'))
        self.LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
        self.WORKERS = int(os.getenv('WORKERS', '4'))
        self.MODEL_PATH = os.getenv('MODEL_PATH', '/models')
        self.DEFAULT_ALGORITHM = os.getenv('DEFAULT_ALGORITHM', 'seasonal_hybrid_esd')
        self.SENSITIVITY_LEVELS = {
            'low': 0.01,
            'medium': 0.005,
            'high': 0.001
        }
        self.DEFAULT_SENSITIVITY = os.getenv('DEFAULT_SENSITIVITY', 'medium')
        
        # Multi-tenant configuration
        self.TENANT_HEADER = os.getenv('TENANT_HEADER', 'X-Tenant-ID')
        self.DEFAULT_TENANT = os.getenv('DEFAULT_TENANT', 'default')
        self.TENANT_ISOLATION = os.getenv('TENANT_ISOLATION', 'True').lower() == 'true'
        
        # Kafka configuration
        self.KAFKA_ENABLED = os.getenv('KAFKA_ENABLED', 'True').lower() == 'true'
        self.KAFKA_BROKERS = os.getenv('KAFKA_BROKERS', 'kafka:9092')
        self.KAFKA_GROUP_ID = os.getenv('KAFKA_GROUP_ID', 'anomaly-detection-group')
        self.KAFKA_AUTO_OFFSET_RESET = os.getenv('KAFKA_AUTO_OFFSET_RESET', 'latest')
        self.KAFKA_INPUT_TOPIC_TEMPLATE = os.getenv('KAFKA_INPUT_TOPIC_TEMPLATE', 'tenant.{}.logs.normalized')
        self.KAFKA_OUTPUT_TOPIC_TEMPLATE = os.getenv('KAFKA_OUTPUT_TOPIC_TEMPLATE', 'tenant.{}.anomalies')
        self.KAFKA_ERROR_TOPIC = os.getenv('KAFKA_ERROR_TOPIC', 'anomaly-detection-errors')
        self.KAFKA_SECURITY_PROTOCOL = os.getenv('KAFKA_SECURITY_PROTOCOL', 'PLAINTEXT')
        self.KAFKA_SASL_MECHANISM = os.getenv('KAFKA_SASL_MECHANISM', None)
        self.KAFKA_SASL_USERNAME = os.getenv('KAFKA_SASL_USERNAME', None)
        self.KAFKA_SASL_PASSWORD = os.getenv('KAFKA_SASL_PASSWORD', None)
        
        # Elasticsearch configuration
        self.ES_ENABLED = os.getenv('ES_ENABLED', 'True').lower() == 'true'
        self.ES_HOSTS = os.getenv('ES_HOSTS', 'http://elasticsearch:9200').split(',')
        self.ES_USERNAME = os.getenv('ES_USERNAME', None)
        self.ES_PASSWORD = os.getenv('ES_PASSWORD', None)
        self.ES_INDEX_TEMPLATE = os.getenv('ES_INDEX_TEMPLATE', 'tenant-{}-logs-*')
        self.ES_ANOMALIES_INDEX_TEMPLATE = os.getenv('ES_ANOMALIES_INDEX_TEMPLATE', 'tenant-{}-anomalies')
        self.ES_SCROLL_SIZE = int(os.getenv('ES_SCROLL_SIZE', '1000'))
        self.ES_SCROLL_TIMEOUT = os.getenv('ES_SCROLL_TIMEOUT', '5m')
        self.ES_MAX_RETRIES = int(os.getenv('ES_MAX_RETRIES', '3'))
        
        # Redis configuration
        self.REDIS_ENABLED = os.getenv('REDIS_ENABLED', 'True').lower() == 'true'
        self.REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
        self.REDIS_PORT = int(os.getenv('REDIS_PORT', '6379'))
        self.REDIS_DB = int(os.getenv('REDIS_DB', '0'))
        self.REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', None)
        self.REDIS_KEY_PREFIX = os.getenv('REDIS_KEY_PREFIX', 'anomaly-detection:')
        self.REDIS_CACHE_TTL = int(os.getenv('REDIS_CACHE_TTL', '3600'))  # 1 hour
        
        # Model configuration
        self.TRAINING_WINDOW_DAYS = int(os.getenv('TRAINING_WINDOW_DAYS', '30'))
        self.PREDICTION_WINDOW_HOURS = int(os.getenv('PREDICTION_WINDOW_HOURS', '24'))
        self.RETRAINING_INTERVAL_HOURS = int(os.getenv('RETRAINING_INTERVAL_HOURS', '24'))
        self.MIN_TRAINING_SAMPLES = int(os.getenv('MIN_TRAINING_SAMPLES', '1000'))
        self.MAX_TRAINING_SAMPLES = int(os.getenv('MAX_TRAINING_SAMPLES', '100000'))
        
        # LSTM model configuration
        self.LSTM_SEQUENCE_LENGTH = int(os.getenv('LSTM_SEQUENCE_LENGTH', '24'))
        self.LSTM_HIDDEN_UNITS = int(os.getenv('LSTM_HIDDEN_UNITS', '64'))
        self.LSTM_DROPOUT_RATE = float(os.getenv('LSTM_DROPOUT_RATE', '0.2'))
        self.LSTM_LEARNING_RATE = float(os.getenv('LSTM_LEARNING_RATE', '0.001'))
        self.LSTM_BATCH_SIZE = int(os.getenv('LSTM_BATCH_SIZE', '32'))
        self.LSTM_EPOCHS = int(os.getenv('LSTM_EPOCHS', '50'))
        
        # Prophet model configuration
        self.PROPHET_CHANGEPOINT_PRIOR_SCALE = float(os.getenv('PROPHET_CHANGEPOINT_PRIOR_SCALE', '0.05'))
        self.PROPHET_SEASONALITY_PRIOR_SCALE = float(os.getenv('PROPHET_SEASONALITY_PRIOR_SCALE', '10.0'))
        self.PROPHET_SEASONALITY_MODE = os.getenv('PROPHET_SEASONALITY_MODE', 'additive')
        self.PROPHET_WEEKLY_SEASONALITY = os.getenv('PROPHET_WEEKLY_SEASONALITY', 'True').lower() == 'true'
        self.PROPHET_DAILY_SEASONALITY = os.getenv('PROPHET_DAILY_SEASONALITY', 'True').lower() == 'true'
        
        # Seasonal-Hybrid ESD configuration
        self.SHESD_MAX_ANOMALIES = float(os.getenv('SHESD_MAX_ANOMALIES', '0.1'))  # Max 10% of points as anomalies
        self.SHESD_ALPHA = float(os.getenv('SHESD_ALPHA', '0.05'))
        self.SHESD_HYBRID_THRESHOLD = float(os.getenv('SHESD_HYBRID_THRESHOLD', '0.95'))
        
        # Create model directories if they don't exist
        os.makedirs(self.MODEL_PATH, exist_ok=True)
        for algorithm in ['seasonal_hybrid_esd', 'prophet', 'lstm']:
            os.makedirs(os.path.join(self.MODEL_PATH, algorithm), exist_ok=True)

# Load configuration
config = Config()

# Set logging level from configuration
logging.getLogger().setLevel(getattr(logging, config.LOG_LEVEL))

# Initialize Flask application
app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
CORS(app)

# Prometheus metrics
REQUESTS = Counter('anomaly_detection_requests_total', 'Total number of requests', ['tenant', 'endpoint', 'method', 'status'])
PREDICTIONS = Counter('anomaly_detection_predictions_total', 'Total number of predictions', ['tenant', 'algorithm', 'status'])
ANOMALIES = Counter('anomaly_detection_anomalies_total', 'Total number of anomalies detected', ['tenant', 'algorithm', 'severity'])
MODEL_TRAINING_TIME = Histogram('anomaly_detection_model_training_seconds', 'Time spent training models', ['tenant', 'algorithm'])
PREDICTION_LATENCY = Histogram('anomaly_detection_prediction_latency_seconds', 'Prediction latency', ['tenant', 'algorithm'])
KAFKA_MESSAGES = Counter('anomaly_detection_kafka_messages_total', 'Total number of Kafka messages processed', ['tenant', 'topic', 'status'])
ES_QUERIES = Counter('anomaly_detection_es_queries_total', 'Total number of Elasticsearch queries', ['tenant', 'operation', 'status'])
CACHE_OPERATIONS = Counter('anomaly_detection_cache_operations_total', 'Total number of cache operations', ['tenant', 'operation', 'status'])
MODEL_SIZE = Gauge('anomaly_detection_model_size_bytes', 'Size of models in bytes', ['tenant', 'algorithm'])
ACTIVE_MODELS = Gauge('anomaly_detection_active_models', 'Number of active models', ['tenant', 'algorithm'])
DATA_POINTS_PROCESSED = Counter('anomaly_detection_data_points_processed_total', 'Total number of data points processed', ['tenant', 'source'])

# Global variables
kafka_consumers = {}
kafka_producer = None
es_client = None
redis_client = None
scheduler = None
models = {}
model_locks = {}

# Base Model class
class BaseAnomalyDetectionModel:
    """Base class for anomaly detection models"""
    
    def __init__(self, tenant_id: str, algorithm: str, config: Config):
        self.tenant_id = tenant_id
        self.algorithm = algorithm
        self.config = config
        self.model = None
        self.scaler = None
        self.is_trained = False
        self.training_data = None
        self.last_trained = None
        self.version = 1
        self.metadata = {
            "tenant_id": tenant_id,
            "algorithm": algorithm,
            "version": self.version,
            "created_at": datetime.now().isoformat(),
            "last_trained": None,
            "training_samples": 0,
            "performance_metrics": {}
        }
        self.model_path = os.path.join(
            self.config.MODEL_PATH, 
            algorithm, 
            f"{tenant_id}_v{self.version}.pkl"
        )
        
        # Initialize logger with tenant context
        self.logger = logging.LoggerAdapter(logger, {"tenant": tenant_id})
    
    def preprocess(self, data: pd.DataFrame) -> pd.DataFrame:
        """Preprocess data for model training or prediction"""
        # Ensure data is sorted by timestamp
        data = data.sort_values('timestamp')
        
        # Handle missing values
        data = data.interpolate(method='time')
        
        # Remove outliers for training (not for prediction)
        if self.is_trained:
            return data
        
        # Simple IQR-based outlier removal for training
        Q1 = data['value'].quantile(0.25)
        Q3 = data['value'].quantile(0.75)
        IQR = Q3 - Q1
        lower_bound = Q1 - 3 * IQR
        upper_bound = Q3 + 3 * IQR
        return data[(data['value'] >= lower_bound) & (data['value'] <= upper_bound)]
    
    def fit(self, data: pd.DataFrame) -> Dict:
        """Train the model with the provided data"""
        raise NotImplementedError("Subclasses must implement the fit method")
    
    def predict(self, data: pd.DataFrame) -> pd.DataFrame:
        """Make predictions with the trained model"""
        raise NotImplementedError("Subclasses must implement the predict method")
    
    def detect_anomalies(self, data: pd.DataFrame, sensitivity: str = None) -> pd.DataFrame:
        """Detect anomalies in the data"""
        raise NotImplementedError("Subclasses must implement the detect_anomalies method")
    
    def save(self) -> str:
        """Save the model to disk"""
        if not self.is_trained:
            raise ValueError("Cannot save an untrained model")
        
        # Update metadata
        self.metadata["last_saved"] = datetime.now().isoformat()
        self.metadata["version"] = self.version
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        # Save model and metadata
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'metadata': self.metadata,
                'training_data': self.training_data.sample(min(1000, len(self.training_data))) if self.training_data is not None else None
            }, f)
        
        self.logger.info(f"Model saved to {self.model_path}")
        MODEL_SIZE.labels(tenant=self.tenant_id, algorithm=self.algorithm).set(os.path.getsize(self.model_path))
        
        return self.model_path
    
    def load(self) -> bool:
        """Load the model from disk"""
        if not os.path.exists(self.model_path):
            self.logger.warning(f"Model file not found: {self.model_path}")
            return False
        
        try:
            with open(self.model_path, 'rb') as f:
                saved_data = pickle.load(f)
                self.model = saved_data['model']
                self.scaler = saved_data['scaler']
                self.metadata = saved_data['metadata']
                self.training_data = saved_data['training_data']
                self.version = self.metadata["version"]
                self.is_trained = True
                self.last_trained = datetime.fromisoformat(self.metadata["last_trained"]) if self.metadata["last_trained"] else None
            
            self.logger.info(f"Model loaded from {self.model_path}")
            MODEL_SIZE.labels(tenant=self.tenant_id, algorithm=self.algorithm).set(os.path.getsize(self.model_path))
            return True
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            return False
    
    def needs_retraining(self) -> bool:
        """Check if the model needs retraining"""
        if not self.is_trained or self.last_trained is None:
            return True
        
        retraining_threshold = datetime.now() - timedelta(hours=self.config.RETRAINING_INTERVAL_HOURS)
        return self.last_trained < retraining_threshold
    
    def get_metadata(self) -> Dict:
        """Get model metadata"""
        return self.metadata


class SeasonalHybridESDModel(BaseAnomalyDetectionModel):
    """Seasonal Hybrid ESD (S-H-ESD) model for anomaly detection"""
    
    def __init__(self, tenant_id: str, config: Config):
        super().__init__(tenant_id, "seasonal_hybrid_esd", config)
    
    def fit(self, data: pd.DataFrame) -> Dict:
        """Train the S-H-ESD model"""
        start_time = time.time()
        self.logger.info(f"Training S-H-ESD model for tenant {self.tenant_id}")
        
        # Preprocess data
        processed_data = self.preprocess(data)
        
        if len(processed_data) < self.config.MIN_TRAINING_SAMPLES:
            raise ValueError(f"Insufficient training data: {len(processed_data)} samples, minimum required: {self.config.MIN_TRAINING_SAMPLES}")
        
        # Store training data statistics for anomaly detection
        self.training_data = processed_data
        self.scaler = StandardScaler()
        self.scaler.fit(processed_data[['value']])
        
        # S-H-ESD doesn't have a model to train, it's applied directly during prediction
        # We just store the statistics of the training data
        self.model = {
            'mean': processed_data['value'].mean(),
            'std': processed_data['value'].std(),
            'median': processed_data['value'].median(),
            'q1': processed_data['value'].quantile(0.25),
            'q3': processed_data['value'].quantile(0.75),
            'min': processed_data['value'].min(),
            'max': processed_data['value'].max(),
        }
        
        # Perform seasonal decomposition to understand the data
        try:
            # Ensure data is evenly spaced for decomposition
            resampled_data = processed_data.set_index('timestamp').resample('1H').mean().dropna()
            if len(resampled_data) > 24:  # Need at least a day of data
                decomposition = seasonal_decompose(resampled_data['value'], model='additive', period=24)
                self.model['seasonal'] = decomposition.seasonal.to_dict()
                self.model['trend'] = decomposition.trend.to_dict()
                self.model['resid'] = decomposition.resid.to_dict()
            else:
                self.model['seasonal'] = None
                self.model['trend'] = None
                self.model['resid'] = None
        except Exception as e:
            self.logger.warning(f"Could not perform seasonal decomposition: {str(e)}")
            self.model['seasonal'] = None
            self.model['trend'] = None
            self.model['resid'] = None
        
        # Update metadata
        self.is_trained = True
        self.last_trained = datetime.now()
        self.metadata["last_trained"] = self.last_trained.isoformat()
        self.metadata["training_samples"] = len(processed_data)
        self.metadata["performance_metrics"] = {
            "training_time": time.time() - start_time
        }
        self.version += 1
        self.metadata["version"] = self.version
        
        # Save the model
        self.model_path = os.path.join(
            self.config.MODEL_PATH, 
            self.algorithm, 
            f"{self.tenant_id}_v{self.version}.pkl"
        )
        self.save()
        
        MODEL_TRAINING_TIME.labels(tenant=self.tenant_id, algorithm=self.algorithm).observe(time.time() - start_time)
        ACTIVE_MODELS.labels(tenant=self.tenant_id, algorithm=self.algorithm).set(1)
        
        return self.metadata
    
    def predict(self, data: pd.DataFrame) -> pd.DataFrame:
        """Make predictions with the S-H-ESD model"""
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        # Preprocess data
        processed_data = self.preprocess(data)
        
        # S-H-ESD doesn't make predictions, it detects anomalies directly
        # Return the original data
        return processed_data
    
    def detect_anomalies(self, data: pd.DataFrame, sensitivity: str = None) -> pd.DataFrame:
        """Detect anomalies using S-H-ESD algorithm"""
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        start_time = time.time()
        
        # Use specified sensitivity or default
        if sensitivity is None:
            sensitivity = self.config.DEFAULT_SENSITIVITY
        
        alpha = self.config.SENSITIVITY_LEVELS.get(sensitivity, self.config.SENSITIVITY_LEVELS['medium'])
        
        # Preprocess data
        processed_data = self.preprocess(data)
        
        # Scale the data
        scaled_values = self.scaler.transform(processed_data[['value']])
        processed_data['scaled_value'] = scaled_values
        
        # Apply S-H-ESD algorithm
        # First, remove seasonal component if available
        if self.model['seasonal'] is not None:
            # Convert seasonal dict back to series
            seasonal_series = pd.Series(self.model['seasonal'])
            
            # Map each timestamp to the corresponding hour of day for seasonal adjustment
            processed_data['hour'] = processed_data['timestamp'].dt.hour
            
            # Apply seasonal adjustment (simplified approach)
            for idx, row in processed_data.iterrows():
                hour = row['hour']
                if hour in seasonal_series:
                    processed_data.at[idx, 'adjusted_value'] = row['value'] - seasonal_series[hour]
                else:
                    processed_data.at[idx, 'adjusted_value'] = row['value']
        else:
            processed_data['adjusted_value'] = processed_data['value']
        
        # Detect anomalies using modified Z-score method (robust to outliers)
        median = processed_data['adjusted_value'].median()
        mad = np.median(np.abs(processed_data['adjusted_value'] - median))
        
        # Avoid division by zero
        if mad == 0:
            mad = np.mean(np.abs(processed_data['adjusted_value'] - median)) or 1
        
        processed_data['z_score'] = 0.6745 * (processed_data['adjusted_value'] - median) / mad
        
        # Mark anomalies based on Z-score threshold derived from sensitivity
        z_threshold = stats.norm.ppf(1 - alpha/2)
        processed_data['is_anomaly'] = np.abs(processed_data['z_score']) > z_threshold
        
        # Calculate anomaly score (0-1 scale)
        max_z = processed_data['z_score'].abs().max()
        if max_z > 0:
            processed_data['anomaly_score'] = processed_data['z_score'].abs() / max_z
        else:
            processed_data['anomaly_score'] = 0
        
        # Determine severity
        processed_data['severity'] = 'normal'
        processed_data.loc[processed_data['is_anomaly'] & (processed_data['anomaly_score'] >= 0.7), 'severity'] = 'critical'
        processed_data.loc[processed_data['is_anomaly'] & (processed_data['anomaly_score'] < 0.7) & (processed_data['anomaly_score'] >= 0.5), 'severity'] = 'high'
        processed_data.loc[processed_data['is_anomaly'] & (processed_data['anomaly_score'] < 0.5), 'severity'] = 'medium'
        
        # Count anomalies by severity
        for severity in ['medium', 'high', 'critical']:
            count = len(processed_data[processed_data['severity'] == severity])
            ANOMALIES.labels(tenant=self.tenant_id, algorithm=self.algorithm, severity=severity).inc(count)
        
        PREDICTION_LATENCY.labels(tenant=self.tenant_id, algorithm=self.algorithm).observe(time.time() - start_time)
        
        return processed_data[['timestamp', 'value', 'is_anomaly', 'anomaly_score', 'severity', 'z_score']]


class ProphetModel(BaseAnomalyDetectionModel):
    """Prophet model for time-series forecasting and anomaly detection"""
    
    def __init__(self, tenant_id: str, config: Config):
        super().__init__(tenant_id, "prophet", config)
    
    def fit(self, data: pd.DataFrame) -> Dict:
        """Train the Prophet model"""
        start_time = time.time()
        self.logger.info(f"Training Prophet model for tenant {self.tenant_id}")
        
        # Preprocess data
        processed_data = self.preprocess(data)
        
        if len(processed_data) < self.config.MIN_TRAINING_SAMPLES:
            raise ValueError(f"Insufficient training data: {len(processed_data)} samples, minimum required: {self.config.MIN_TRAINING_SAMPLES}")
        
        # Store training data
        self.training_data = processed_data
        
        # Prepare data for Prophet (requires 'ds' and 'y' columns)
        prophet_data = processed_data.rename(columns={'timestamp': 'ds', 'value': 'y'})
        
        # Initialize and train Prophet model
        self.model = Prophet(
            changepoint_prior_scale=self.config.PROPHET_CHANGEPOINT_PRIOR_SCALE,
            seasonality_prior_scale=self.config.PROPHET_SEASONALITY_PRIOR_SCALE,
            seasonality_mode=self.config.PROPHET_SEASONALITY_MODE,
            weekly_seasonality=self.config.PROPHET_WEEKLY_SEASONALITY,
            daily_seasonality=self.config.PROPHET_DAILY_SEASONALITY
        )
        
        # Add additional seasonalities if enough data
        if len(prophet_data) > 24 * 7:  # More than a week of hourly data
            self.model.add_seasonality(name='hourly', period=24, fourier_order=5)
        
        # Fit the model
        self.model.fit(prophet_data)
        
        # Calculate performance metrics using cross-validation
        try:
            if len(prophet_data) >= 30:  # Only if we have enough data
                cv_results = cross_validation(
                    self.model, 
                    initial='7 days', 
                    period='1 day', 
                    horizon='1 day'
                )
                performance = performance_metrics(cv_results)
                metrics = {
                    'mse': float(performance['mse'].mean()),
                    'rmse': float(performance['rmse'].mean()),
                    'mae': float(performance['mae'].mean()),
                    'mape': float(performance['mape'].mean()),
                    'coverage': float(performance['coverage'].mean())
                }
            else:
                # Make future predictions for the training data
                future = self.model.make_future_dataframe(periods=0)
                forecast = self.model.predict(future)
                
                # Calculate metrics
                y_true = prophet_data['y'].values
                y_pred = forecast['yhat'].values[:len(y_true)]
                
                metrics = {
                    'mse': mean_squared_error(y_true, y_pred),
                    'rmse': np.sqrt(mean_squared_error(y_true, y_pred)),
                    'mae': mean_absolute_error(y_true, y_pred),
                    'r2': r2_score(y_true, y_pred)
                }
        except Exception as e:
            self.logger.warning(f"Error calculating performance metrics: {str(e)}")
            metrics = {}
        
        # Update metadata
        self.is_trained = True
        self.last_trained = datetime.now()
        self.metadata["last_trained"] = self.last_trained.isoformat()
        self.metadata["training_samples"] = len(processed_data)
        self.metadata["performance_metrics"] = {
            "training_time": time.time() - start_time,
            **metrics
        }
        self.version += 1
        self.metadata["version"] = self.version
        
        # Save the model
        self.model_path = os.path.join(
            self.config.MODEL_PATH, 
            self.algorithm, 
            f"{self.tenant_id}_v{self.version}.pkl"
        )
        self.save()
        
        MODEL_TRAINING_TIME.labels(tenant=self.tenant_id, algorithm=self.algorithm).observe(time.time() - start_time)
        ACTIVE_MODELS.labels(tenant=self.tenant_id, algorithm=self.algorithm).set(1)
        
        return self.metadata
    
    def predict(self, data: pd.DataFrame) -> pd.DataFrame:
        """Make predictions with the Prophet model"""
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        # Prepare data for Prophet
        prophet_data = data.rename(columns={'timestamp': 'ds'})
        
        # Make predictions
        forecast = self.model.predict(prophet_data)
        
        # Prepare result dataframe
        result = pd.DataFrame({
            'timestamp': prophet_data['ds'],
            'value': data['value'],
            'prediction': forecast['yhat'],
            'prediction_lower': forecast['yhat_lower'],
            'prediction_upper': forecast['yhat_upper'],
            'trend': forecast['trend']
        })
        
        return result
    
    def detect_anomalies(self, data: pd.DataFrame, sensitivity: str = None) -> pd.DataFrame:
        """Detect anomalies using Prophet predictions"""
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        start_time = time.time()
        
        # Use specified sensitivity or default
        if sensitivity is None:
            sensitivity = self.config.DEFAULT_SENSITIVITY
        
        # Get sensitivity threshold
        threshold = self.config.SENSITIVITY_LEVELS.get(sensitivity, self.config.SENSITIVITY_LEVELS['medium'])
        
        # Make predictions
        predictions = self.predict(data)
        
        # Calculate normalized prediction error
        predictions['error'] = np.abs(predictions['value'] - predictions['prediction'])
        predictions['normalized_error'] = (predictions['error'] / 
                                          (predictions['prediction_upper'] - predictions['prediction_lower']))
        
        # Detect anomalies based on prediction intervals
        predictions['is_anomaly'] = (predictions['value'] < predictions['prediction_lower']) | \
                                    (predictions['value'] > predictions['prediction_upper'])
        
        # Calculate anomaly score (0-1 scale)
        max_error = predictions['normalized_error'].max()
        if max_error > 0:
            predictions['anomaly_score'] = predictions['normalized_error'] / max_error
        else:
            predictions['anomaly_score'] = 0
        
        # Determine severity
        predictions['severity'] = 'normal'
        predictions.loc[predictions['is_anomaly'] & (predictions['anomaly_score'] >= 0.7), 'severity'] = 'critical'
        predictions.loc[predictions['is_anomaly'] & (predictions['anomaly_score'] < 0.7) & (predictions['anomaly_score'] >= 0.5), 'severity'] = 'high'
        predictions.loc[predictions['is_anomaly'] & (predictions['anomaly_score'] < 0.5), 'severity'] = 'medium'
        
        # Count anomalies by severity
        for severity in ['medium', 'high', 'critical']:
            count = len(predictions[predictions['severity'] == severity])
            ANOMALIES.labels(tenant=self.tenant_id, algorithm=self.algorithm, severity=severity).inc(count)
        
        PREDICTION_LATENCY.labels(tenant=self.tenant_id, algorithm=self.algorithm).observe(time.time() - start_time)
        
        return predictions[['timestamp', 'value', 'prediction', 'is_anomaly', 'anomaly_score', 'severity']]


class LSTMModel(BaseAnomalyDetectionModel):
    """LSTM model for time-series forecasting and anomaly detection"""
    
    def __init__(self, tenant_id: str, config: Config):
        super().__init__(tenant_id, "lstm", config)
        # Set memory growth for GPU if available
        physical_devices = tf.config.list_physical_devices('GPU')
        if physical_devices:
            try:
                for device in physical_devices:
                    tf.config.experimental.set_memory_growth(device, True)
                self.logger.info(f"GPU acceleration enabled with {len(physical_devices)} devices")
            except Exception as e:
                self.logger.warning(f"Could not set memory growth for GPU: {str(e)}")
    
    def _create_sequences(self, data: np.ndarray, seq_length: int) -> Tuple[np.ndarray, np.ndarray]:
        """Create sequences for LSTM training"""
        xs, ys = [], []
        for i in range(len(data) - seq_length):
            x = data[i:i+seq_length]
            y = data[i+seq_length]
            xs.append(x)
            ys.append(y)
        return np.array(xs), np.array(ys)
    
    def fit(self, data: pd.DataFrame) -> Dict:
        """Train the LSTM model"""
        start_time = time.time()
        self.logger.info(f"Training LSTM model for tenant {self.tenant_id}")
        
        # Preprocess data
        processed_data = self.preprocess(data)
        
        if len(processed_data) < self.config.MIN_TRAINING_SAMPLES:
            raise ValueError(f"Insufficient training data: {len(processed_data)} samples, minimum required: {self.config.MIN_TRAINING_SAMPLES}")
        
        # Store training data
        self.training_data = processed_data
        
        # Scale the data
        self.scaler = MinMaxScaler(feature_range=(0, 1))
        scaled_data = self.scaler.fit_transform(processed_data[['value']])
        
        # Create sequences for LSTM
        seq_length = self.config.LSTM_SEQUENCE_LENGTH
        x_train, y_train = self._create_sequences(scaled_data, seq_length)
        
        # Reshape input for LSTM [samples, time steps, features]
        x_train = x_train.reshape(x_train.shape[0], x_train.shape[1], 1)
        
        # Build LSTM model
        model = Sequential()
        model.add(LSTM(units=self.config.LSTM_HIDDEN_UNITS, 
                       return_sequences=True, 
                       input_shape=(seq_length, 1)))
        model.add(Dropout(self.config.LSTM_DROPOUT_RATE))
        model.add(LSTM(units=self.config.LSTM_HIDDEN_UNITS//2, 
                       return_sequences=False))
        model.add(Dropout(self.config.LSTM_DROPOUT_RATE))
        model.add(Dense(units=1))
        
        # Compile model
        optimizer = Adam(learning_rate=self.config.LSTM_LEARNING_RATE)
        model.compile(optimizer=optimizer, loss='mean_squared_error')
        
        # Early stopping and model checkpoint
        callbacks = [
            EarlyStopping(monitor='val_loss', patience=10, restore_best_weights=True),
            ModelCheckpoint(
                filepath=os.path.join(self.config.MODEL_PATH, 'lstm', f"{self.tenant_id}_best_model.h5"),
                monitor='val_loss',
                save_best_only=True
            )
        ]
        
        # Train model
        history = model.fit(
            x_train, y_train,
            epochs=self.config.LSTM_EPOCHS,
            batch_size=self.config.LSTM_BATCH_SIZE,
            validation_split=0.2,
            callbacks=callbacks,
            verbose=0
        )
        
        # Store the model
        self.model = model
        
        # Calculate performance metrics
        train_loss = history.history['loss'][-1]
        val_loss = history.history['val_loss'][-1]
        
        # Make predictions on training data for additional metrics
        train_predictions = model.predict(x_train)
        train_predictions = self.scaler.inverse_transform(train_predictions)
        y_train_inv = self.scaler.inverse_transform(y_train.reshape(-1, 1))
        
        mse = mean_squared_error(y_train_inv, train_predictions)
        rmse = np.sqrt(mse)
        mae = mean_absolute_error(y_train_inv, train_predictions)
        
        # Update metadata
        self.is_trained = True
        self.last_trained = datetime.now()
        self.metadata["last_trained"] = self.last_trained.isoformat()
        self.metadata["training_samples"] = len(processed_data)
        self.metadata["performance_metrics"] = {
            "training_time": time.time() - start_time,
            "train_loss": float(train_loss),
            "val_loss": float(val_loss),
            "mse": float(mse),
            "rmse": float(rmse),
            "mae": float(mae)
        }
        self.version += 1
        self.metadata["version"] = self.version
        
        # Save the model
        self.model_path = os.path.join(
            self.config.MODEL_PATH, 
            self.algorithm, 
            f"{self.tenant_id}_v{self.version}.pkl"
        )
        self.save()
        
        # Save TensorFlow model separately
        tf_model_path = os.path.join(
            self.config.MODEL_PATH, 
            self.algorithm, 
            f"{self.tenant_id}_v{self.version}_tf.h5"
        )
        model.save(tf_model_path)
        
        MODEL_TRAINING_TIME.labels(tenant=self.tenant_id, algorithm=self.algorithm).observe(time.time() - start_time)
        ACTIVE_MODELS.labels(tenant=self.tenant_id, algorithm=self.algorithm).set(1)
        
        return self.metadata
    
    def save(self) -> str:
        """Save the model to disk"""
        if not self.is_trained:
            raise ValueError("Cannot save an untrained model")
        
        # Update metadata
        self.metadata["last_saved"] = datetime.now().isoformat()
        self.metadata["version"] = self.version
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        # Save TensorFlow model separately
        tf_model_path = os.path.join(
            self.config.MODEL_PATH, 
            self.algorithm, 
            f"{self.tenant_id}_v{self.version}_tf.h5"
        )
        self.model.save(tf_model_path)
        
        # Save metadata and scaler
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'scaler': self.scaler,
                'metadata': self.metadata,
                'training_data': self.training_data.sample(min(1000, len(self.training_data))) if self.training_data is not None else None,
                'tf_model_path': tf_model_path
            }, f)
        
        self.logger.info(f"Model saved to {self.model_path}")
        MODEL_SIZE.labels(tenant=self.tenant_id, algorithm=self.algorithm).set(
            os.path.getsize(self.model_path) + os.path.getsize(tf_model_path)
        )
        
        return self.model_path
    
    def load(self) -> bool:
        """Load the model from disk"""
        if not os.path.exists(self.model_path):
            self.logger.warning(f"Model file not found: {self.model_path}")
            return False
        
        try:
            with open(self.model_path, 'rb') as f:
                saved_data = pickle.load(f)
                self.scaler = saved_data['scaler']
                self.metadata = saved_data['metadata']
                self.training_data = saved_data['training_data']
                self.version = self.metadata["version"]
                tf_model_path = saved_data['tf_model_path']
            
            # Load TensorFlow model
            if os.path.exists(tf_model_path):
                self.model = load_model(tf_model_path)
                self.is_trained = True
                self.last_trained = datetime.fromisoformat(self.metadata["last_trained"]) if self.metadata["last_trained"] else None
                
                self.logger.info(f"Model loaded from {self.model_path} and {tf_model_path}")
                MODEL_SIZE.labels(tenant=self.tenant_id, algorithm=self.algorithm).set(
                    os.path.getsize(self.model_path) + os.path.getsize(tf_model_path)
                )
                return True
            else:
                self.logger.error(f"TensorFlow model file not found: {tf_model_path}")
                return False
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            return False
    
    def predict(self, data: pd.DataFrame) -> pd.DataFrame:
        """Make predictions with the LSTM model"""
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        # Preprocess data
        processed_data = self.preprocess(data)
        
        # Scale the data
        scaled_data = self.scaler.transform(processed_data[['value']])
        
        # Create sequences for prediction
        seq_length = self.config.LSTM_SEQUENCE_LENGTH
        predictions = []
        
        # For each prediction point, create a sequence and predict
        for i in range(len(scaled_data) - seq_length):
            x = scaled_data[i:i+seq_length].reshape(1, seq_length, 1)
            pred = self.model.predict(x, verbose=0)[0][0]
            predictions.append(pred)
        
        # Pad with NaN for the first seq_length points
        padding = [np.nan] * seq_length
        all_predictions = np.array(padding + predictions)
        
        # Inverse transform predictions
        all_predictions = all_predictions.reshape(-1, 1)
        all_predictions_inv = np.zeros_like(all_predictions)
        
        # Only inverse transform non-NaN values
        mask = ~np.isnan(all_predictions)
        all_predictions_inv[mask] = self.scaler.inverse_transform(all_predictions[mask].reshape(-1, 1)).flatten()
        
        # Prepare result dataframe
        result = pd.DataFrame({
            'timestamp': processed_data['timestamp'],
            'value': processed_data['value'],
            'prediction': all_predictions_inv.flatten()
        })
        
        return result
    
    def detect_anomalies(self, data: pd.DataFrame, sensitivity: str = None) -> pd.DataFrame:
        """Detect anomalies using LSTM predictions"""
        if not self.is_trained:
            raise ValueError("Model not trained")
        
        start_time = time.time()
        
        # Use specified sensitivity or default
        if sensitivity is None:
            sensitivity = self.config.DEFAULT_SENSITIVITY
        
        # Get sensitivity threshold
        alpha = self.config.SENSITIVITY_LEVELS.get(sensitivity, self.config.SENSITIVITY_LEVELS['medium'])
        
        # Make predictions
        predictions = self.predict(data)
        
        # Calculate prediction errors
        predictions['error'] = np.abs(predictions['value'] - predictions['prediction'])
        
        # Calculate error statistics from training data predictions
        if self.training_data is not None:
            train_predictions = self.predict(self.training_data)
            train_errors = np.abs(train_predictions['value'] - train_predictions['prediction'])
            error_mean = train_errors.mean()
            error_std = train_errors.std()
            
            # Calculate z-scores for errors
            predictions['z_score'] = (predictions['error'] - error_mean) / (error_std if error_std > 0 else 1)
            
            # Detect anomalies based on z-score threshold derived from sensitivity
            z_threshold = stats.norm.ppf(1 - alpha/2)
            predictions['is_anomaly'] = predictions['z_score'] > z_threshold
            
            # Calculate anomaly score (0-1 scale)
            max_z = predictions['z_score'].max()
            if max_z > 0:
                predictions['anomaly_score'] = predictions['z_score'] / max_z
            else:
                predictions['anomaly_score'] = 0
        else:
            # Fallback if no training data is available
            # Use simple threshold based on error distribution
            error_threshold = predictions['error'].quantile(1 - alpha)
            predictions['is_anomaly'] = predictions['error'] > error_threshold
            predictions['anomaly_score'] = predictions['error'] / predictions['error'].max() if predictions['error'].max() > 0 else 0
            predictions['z_score'] = (predictions['error'] - predictions['error'].mean()) / predictions['error'].std() if predictions['error'].std() > 0 else 0
        
        # Determine severity
        predictions['severity'] = 'normal'
        predictions.loc[predictions['is_anomaly'] & (predictions['anomaly_score'] >= 0.7), 'severity'] = 'critical'
        predictions.loc[predictions['is_anomaly'] & (predictions['anomaly_score'] < 0.7) & (predictions['anomaly_score'] >= 0.5), 'severity'] = 'high'
        predictions.loc[predictions['is_anomaly'] & (predictions['anomaly_score'] < 0.5), 'severity'] = 'medium'
        
        # Count anomalies by severity
        for severity in ['medium', 'high', 'critical']:
            count = len(predictions[predictions['severity'] == severity])
            ANOMALIES.labels(tenant=self.tenant_id, algorithm=self.algorithm, severity=severity).inc(count)
        
        PREDICTION_LATENCY.labels(tenant=self.tenant_id, algorithm=self.algorithm).observe(time.time() - start_time)
        
        return predictions[['timestamp', 'value', 'prediction', 'is_anomaly', 'anomaly_score', 'severity', 'z_score']]


# Model factory function
def get_model(tenant_id: str, algorithm: str = None) -> BaseAnomalyDetectionModel:
    """Get or create a model for the specified tenant and algorithm"""
    if algorithm is None:
        algorithm = config.DEFAULT_ALGORITHM
    
    model_key = f"{tenant_id}_{algorithm}"
    
    # Create lock if it doesn't exist
    if model_key not in model_locks:
        model_locks[model_key] = threading.Lock()
    
    with model_locks[model_key]:
        # Check if model exists in memory
        if model_key in models:
            return models[model_key]
        
        # Create new model
        if algorithm == "seasonal_hybrid_esd":
            model = SeasonalHybridESDModel(tenant_id, config)
        elif algorithm == "prophet":
            model = ProphetModel(tenant_id, config)
        elif algorithm == "lstm":
            model = LSTMModel(tenant_id, config)
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        # Try to load model from disk
        model.load()
        
        # Store model in memory
        models[model_key] = model
        
        return model


# Initialize Elasticsearch client
def init_elasticsearch():
    """Initialize Elasticsearch client"""
    global es_client
    
    if not config.ES_ENABLED:
        logger.info("Elasticsearch integration disabled")
        return None
    
    try:
        es_options = {
            'hosts': config.ES_HOSTS,
            'retry_on_timeout': True,
            'max_retries': config.ES_MAX_RETRIES,
            'timeout': 30
        }
        
        if config.ES_USERNAME and config.ES_PASSWORD:
            es_options['http_auth'] = (config.ES_USERNAME, config.ES_PASSWORD)
        
        es_client = Elasticsearch(**es_options)
        
        # Test connection
        if es_client.ping():
            logger.info(f"Connected to Elasticsearch: {config.ES_HOSTS}")
            return es_client
        else:
            logger.error(f"Failed to connect to Elasticsearch: {config.ES_HOSTS}")
            return None
    except Exception as e:
        logger.error(f"Error connecting to Elasticsearch: {str(e)}")
        return None


# Initialize Redis client
def init_redis():
    """Initialize Redis client"""
    global redis_client
    
    if not config.REDIS_ENABLED:
        logger.info("Redis integration disabled")
        return None
    
    try:
        redis_options = {
            'host': config.REDIS_HOST,
            'port': config.REDIS_PORT,
            'db': config.REDIS_DB,
            'decode_responses': False
        }
        
        if config.REDIS_PASSWORD:
            redis_options['password'] = config.REDIS_PASSWORD
        
        redis_client = redis.Redis(**redis_options)
        
        # Test connection
        redis_client.ping()
        logger.info(f"Connected to Redis: {config.REDIS_HOST}:{config.REDIS_PORT}")
        return redis_client
    except Exception as e:
        logger.error(f"Error connecting to Redis: {str(e)}")
        return None


# Initialize Kafka producer
def init_kafka_producer():
    """Initialize Kafka producer"""
    global kafka_producer
    
    if not config.KAFKA_ENABLED:
        logger.info("Kafka integration disabled")
        return None
    
    try:
        producer_config = {
            'bootstrap.servers': config.KAFKA_BROKERS,
            'client.id': 'anomaly-detection-producer'
        }
        
        # Add security configuration if enabled
        if config.KAFKA_SECURITY_PROTOCOL:
            producer_config['security.protocol'] = config.KAFKA_SECURITY_PROTOCOL
            
            if config.KAFKA_SASL_MECHANISM and config.KAFKA_SASL_USERNAME and config.KAFKA_SASL_PASSWORD:
                producer_config['sasl.mechanism'] = config.KAFKA_SASL_MECHANISM
                producer_config['sasl.username'] = config.KAFKA_SASL_USERNAME
                producer_config['sasl.password'] = config.KAFKA_SASL_PASSWORD
        
        kafka_producer = Producer(producer_config)
        logger.info(f"Initialized Kafka producer: {config.KAFKA_BROKERS}")
        return kafka_producer
    except Exception as e:
        logger.error(f"Error initializing Kafka producer: {str(e)}")
        return None


# Initialize Kafka consumers
def init_kafka_consumers():
    """Initialize Kafka consumers for all tenants"""
    global kafka_consumers
    
    if not config.KAFKA_ENABLED:
        logger.info("Kafka integration disabled")
        return {}
    
    # Get all tenants from Elasticsearch or a configuration file
    tenants = get_all_tenants()
    
    for tenant_id in tenants:
        try:
            # Create consumer for tenant
            create_kafka_consumer(tenant_id)
        except Exception as e:
            logger.error(f"Error creating Kafka consumer for tenant {tenant_id}: {str(e)}")
    
    return kafka_consumers


# Create Kafka consumer for a tenant
def create_kafka_consumer(tenant_id: str):
    """Create a Kafka consumer for a specific tenant"""
    if tenant_id in kafka_consumers:
        return kafka_consumers[tenant_id]
    
    try:
        consumer_config = {
            'bootstrap.servers': config.KAFKA_BROKERS,
            'group.id': f"{config.KAFKA_GROUP_ID}-{tenant_id}",
            'auto.offset.reset': config.KAFKA_AUTO_OFFSET_RESET,
            'enable.auto.commit': True,
            'max.poll.interval.ms': 300000  # 5 minutes
        }
        
        # Add security configuration if enabled
        if config.KAFKA_SECURITY_PROTOCOL:
            consumer_config['security.protocol'] = config.KAFKA_SECURITY_PROTOCOL
            
            if config.KAFKA_SASL_MECHANISM and config.KAFKA_SASL_USERNAME and config.KAFKA_SASL_PASSWORD:
                consumer_config['sasl.mechanism'] = config.KAFKA_SASL_MECHANISM
                consumer_config['sasl.username'] = config.KAFKA_SASL_USERNAME
                consumer_config['sasl.password'] = config.KAFKA_SASL_PASSWORD
        
        consumer = Consumer(consumer_config)
        
        # Subscribe to tenant's topic
        topic = config.KAFKA_INPUT_TOPIC_TEMPLATE.format(tenant_id)
        consumer.subscribe([topic])
        
        # Store consumer
        kafka_consumers[tenant_id] = {
            'consumer': consumer,
            'topic': topic,
            'thread': None,
            'running': False
        }
        
        logger.info(f"Created Kafka consumer for tenant {tenant_id}, topic {topic}")
        return kafka_consumers[tenant_id]
    except Exception as e:
        logger.error(f"Error creating Kafka consumer for tenant {tenant_id}: {str(e)}")
        return None


# Start Kafka consumer thread for a tenant
def start_kafka_consumer_thread(tenant_id: str):
    """Start a Kafka consumer thread for a specific tenant"""
    if tenant_id not in kafka_consumers:
        create_kafka_consumer(tenant_id)
    
    if kafka_consumers[tenant_id]['thread'] is not None and kafka_consumers[tenant_id]['running']:
        return
    
    def consume_messages():
        consumer = kafka_consumers[tenant_id]['consumer']
        topic = kafka_consumers[tenant_id]['topic']
        output_topic = config.KAFKA_OUTPUT_TOPIC_TEMPLATE.format(tenant_id)
        tenant_logger = logging.LoggerAdapter(logger, {"tenant": tenant_id})
        
        tenant_logger.info(f"Starting Kafka consumer thread for topic {topic}")
        
        # Get model for tenant
        model = get_model(tenant_id, config.DEFAULT_ALGORITHM)
        
        # Check if model is trained, if not, try to train it
        if not model.is_trained:
            try:
                tenant_logger.info(f"Model not trained, attempting to train from historical data")
                train_model_from_history(tenant_id, config.DEFAULT_ALGORITHM)
            except Exception as e:
                tenant_logger.warning(f"Failed to train model from historical data: {str(e)}")
        
        # Set running flag
        kafka_consumers[tenant_id]['running'] = True
        
        try:
            while kafka_consumers[tenant_id]['running']:
                try:
                    # Poll for messages
                    msg = consumer.poll(1.0)
                    
                    if msg is None:
                        continue
                    
                    if msg.error():
                        if msg.error().code() == KafkaError._PARTITION_EOF:
                            # End of partition event
                            tenant_logger.debug(f"Reached end of partition {msg.partition()}")
                        else:
                            # Error
                            tenant_logger.error(f"Error consuming message: {msg.error()}")
                        continue
                    
                    # Process message
                    try:
                        # Parse message
                        message_value = msg.value().decode('utf-8')
                        data = json.loads(message_value)
                        
                        # Convert to DataFrame
                        if isinstance(data, list):
                            df = pd.DataFrame(data)
                        else:
                            df = pd.DataFrame([data])
                        
                        # Ensure required columns
                        if 'timestamp' not in df.columns or 'value' not in df.columns:
                            tenant_logger.warning(f"Message missing required columns: {df.columns}")
                            continue
                        
                        # Convert timestamp to datetime
                        df['timestamp'] = pd.to_datetime(df['timestamp'])
                        
                        # Detect anomalies
                        result = model.detect_anomalies(df)
                        
                        # Filter anomalies
                        anomalies = result[result['is_anomaly']]
                        
                        # If anomalies found, send to output topic
                        if len(anomalies) > 0:
                            for _, row in anomalies.iterrows():
                                # Create anomaly message
                                anomaly_msg = {
                                    'timestamp': row['timestamp'].isoformat(),
                                    'value': float(row['value']),
                                    'anomaly_score': float(row['anomaly_score']),
                                    'severity': row['severity'],
                                    'algorithm': model.algorithm,
                                    'tenant_id': tenant_id,
                                    'detection_time': datetime.now().isoformat()
                                }
                                
                                # Send to Kafka
                                kafka_producer.produce(
                                    output_topic,
                                    json.dumps(anomaly_msg).encode('utf-8')
                                )
                            
                            # Flush producer
                            kafka_producer.flush()
                            
                            tenant_logger.info(f"Detected {len(anomalies)} anomalies, sent to {output_topic}")
                            KAFKA_MESSAGES.labels(tenant=tenant_id, topic=output_topic, status='success').inc(len(anomalies))
                        
                        # Update metrics
                        DATA_POINTS_PROCESSED.labels(tenant=tenant_id, source='kafka').inc(len(df))
                        KAFKA_MESSAGES.labels(tenant=tenant_id, topic=topic, status='success').inc(1)
                        
                    except Exception as e:
                        tenant_logger.error(f"Error processing message: {str(e)}")
                        KAFKA_MESSAGES.labels(tenant=tenant_id, topic=topic, status='error').inc(1)
                        
                        # Send error to error topic
                        if kafka_producer:
                            error_msg = {
                                'tenant_id': tenant_id,
                                'error': str(e),
                                'timestamp': datetime.now().isoformat(),
                                'topic': topic
                            }
                            kafka_producer.produce(
                                config.KAFKA_ERROR_TOPIC,
                                json.dumps(error_msg).encode('utf-8')
                            )
                            kafka_producer.flush()
                
                except Exception as e:
                    tenant_logger.error(f"Error in Kafka consumer loop: {str(e)}")
                    time.sleep(5)  # Wait before retrying
        
        except Exception as e:
            tenant_logger.error(f"Fatal error in Kafka consumer thread: {str(e)}")
        
        finally:
            # Clean up
            try:
                consumer.close()
                tenant_logger.info(f"Kafka consumer closed for tenant {tenant_id}")
            except Exception as e:
                tenant_logger.error(f"Error closing Kafka consumer: {str(e)}")
            
            kafka_consumers[tenant_id]['running'] = False
    
    # Create and start thread
    thread = threading.Thread(target=consume_messages)
    thread.daemon = True
    thread.start()
    
    # Store thread
    kafka_consumers[tenant_id]['thread'] = thread
    
    logger.info(f"Started Kafka consumer thread for tenant {tenant_id}")


# Stop Kafka consumer thread for a tenant
def stop_kafka_consumer_thread(tenant_id: str):
    """Stop a Kafka consumer thread for a specific tenant"""
    if tenant_id not in kafka_consumers:
        return
    
    if kafka_consumers[tenant_id]['thread'] is None:
        return
    
    # Set running flag to False
    kafka_consumers[tenant_id]['running'] = False
    
    # Wait for thread to finish
    kafka_consumers[tenant_id]['thread'].join(timeout=30)
    
    # Close consumer
    try:
        kafka_consumers[tenant_id]['consumer'].close()
    except Exception as e:
        logger.error(f"Error closing Kafka consumer for tenant {tenant_id}: {str(e)}")
    
    # Clear thread
    kafka_consumers[tenant_id]['thread'] = None
    
    logger.info(f"Stopped Kafka consumer thread for tenant {tenant_id}")


# Get all tenants
def get_all_tenants() -> List[str]:
    """Get all tenants from Elasticsearch or configuration"""
    # For now, return default tenant
    return [config.DEFAULT_TENANT]


# Get data from Elasticsearch
def get_data_from_elasticsearch(tenant_id: str, start_time: str = None, end_time: str = None, 
                                limit: int = 10000) -> pd.DataFrame:
    """Get data from Elasticsearch for a specific tenant"""
    if not es_client:
        raise ValueError("Elasticsearch client not initialized")
    
    tenant_logger = logging.LoggerAdapter(logger, {"tenant": tenant_id})
    
    try:
        # Set default time range if not provided
        if not start_time:
            start_time = (datetime.now() - timedelta(days=config.TRAINING_WINDOW_DAYS)).isoformat()
        if not end_time:
            end_time = datetime.now().isoformat()
        
        # Build query
        index = config.ES_INDEX_TEMPLATE.format(tenant_id)
        query = {
            "size": config.ES_SCROLL_SIZE,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time,
                                    "lte": end_time
                                }
                            }
                        }
                    ]
                }
            },
            "sort": [
                {"@timestamp": {"order": "asc"}}
            ]
        }
        
        # Execute scroll query
        data = []
        resp = es_client.search(
            index=index,
            body=query,
            scroll=config.ES_SCROLL_TIMEOUT
        )
        
        # Get scroll ID
        scroll_id = resp['_scroll_id']
        
        # Process first batch
        for hit in resp['hits']['hits']:
            data.append(hit['_source'])
        
        # Continue scrolling until no more results or limit reached
        while len(resp['hits']['hits']) > 0 and len(data) < limit:
            resp = es_client.scroll(
                scroll_id=scroll_id,
                scroll=config.ES_SCROLL_TIMEOUT
            )
            
            for hit in resp['hits']['hits']:
                data.append(hit['_source'])
                
                if len(data) >= limit:
                    break
        
        # Clear scroll
        es_client.clear_scroll(scroll_id=scroll_id)
        
        # Convert to DataFrame
        df = pd.DataFrame(data)
        
        # Extract timestamp and value fields
        if '@timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['@timestamp'])
        else:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Extract value field - can be in different places depending on data format
        if 'value' not in df.columns:
            # Try to find value in common locations
            if 'metric' in df.columns and 'value' in df['metric'].iloc[0]:
                df['value'] = df['metric'].apply(lambda x: x['value'])
            elif 'fields' in df.columns and 'value' in df['fields'].iloc[0]:
                df['value'] = df['fields'].apply(lambda x: x['value'])
            else:
                # Try to find a numeric field
                numeric_cols = df.select_dtypes(include=[np.number]).columns
                if len(numeric_cols) > 0:
                    df['value'] = df[numeric_cols[0]]
                else:
                    raise ValueError("Could not find value field in data")
        
        # Ensure value is numeric
        df['value'] = pd.to_numeric(df['value'], errors='coerce')
        
        # Drop rows with missing values
        df = df.dropna(subset=['timestamp', 'value'])
        
        # Select only needed columns
        df = df[['timestamp', 'value']]
        
        tenant_logger.info(f"Retrieved {len(df)} records from Elasticsearch")
        ES_QUERIES.labels(tenant=tenant_id, operation='search', status='success').inc()
        DATA_POINTS_PROCESSED.labels(tenant=tenant_id, source='elasticsearch').inc(len(df))
        
        return df
    
    except Exception as e:
        tenant_logger.error(f"Error retrieving data from Elasticsearch: {str(e)}")
        ES_QUERIES.labels(tenant=tenant_id, operation='search', status='error').inc()
        raise


# Store anomalies in Elasticsearch
def store_anomalies_in_elasticsearch(tenant_id: str, anomalies: pd.DataFrame) -> bool:
    """Store detected anomalies in Elasticsearch"""
    if not es_client:
        raise ValueError("Elasticsearch client not initialized")
    
    if len(anomalies) == 0:
        return True
    
    tenant_logger = logging.LoggerAdapter(logger, {"tenant": tenant_id})
    
    try:
        # Prepare index
        index = config.ES_ANOMALIES_INDEX_TEMPLATE.format(tenant_id)
        
        # Check if index exists, create if not
        if not es_client.indices.exists(index=index):
            # Create index with mapping
            es_client.indices.create(
                index=index,
                body={
                    "mappings": {
                        "properties": {
                            "timestamp": {"type": "date"},
                            "detection_time": {"type": "date"},
                            "value": {"type": "float"},
                            "anomaly_score": {"type": "float"},
                            "severity": {"type": "keyword"},
                            "algorithm": {"type": "keyword"},
                            "tenant_id": {"type": "keyword"}
                        }
                    },
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 1
                    }
                }
            )
        
        # Prepare documents
        actions = []
        for _, row in anomalies.iterrows():
            doc = {
                "timestamp": row['timestamp'].isoformat(),
                "value": float(row['value']),
                "anomaly_score": float(row['anomaly_score']),
                "severity": row['severity'],
                "algorithm": row.get('algorithm', 'unknown'),
                "tenant_id": tenant_id,
                "detection_time": datetime.now().isoformat()
            }
            
            # Add prediction if available
            if 'prediction' in row:
                doc['prediction'] = float(row['prediction'])
            
            # Add z_score if available
            if 'z_score' in row:
                doc['z_score'] = float(row['z_score'])
            
            actions.append({
                "_index": index,
                "_source": doc
            })
        
        # Bulk index
        if actions:
            helpers.bulk(es_client, actions)
            
            tenant_logger.info(f"Stored {len(actions)} anomalies in Elasticsearch")
            ES_QUERIES.labels(tenant=tenant_id, operation='index', status='success').inc()
            
            return True
    
    except Exception as e:
        tenant_logger.error(f"Error storing anomalies in Elasticsearch: {str(e)}")
        ES_QUERIES.labels(tenant=tenant_id, operation='index', status='error').inc()
        
        return False


# Get data with caching
def get_data_with_cache(tenant_id: str, start_time: str = None, end_time: str = None, 
                        limit: int = 10000) -> pd.DataFrame:
    """Get data with Redis caching"""
    if not redis_client:
        # If Redis is not available, get data directly
        return get_data_from_elasticsearch(tenant_id, start_time, end_time, limit)
    
    tenant_logger = logging.LoggerAdapter(logger, {"tenant": tenant_id})
    
    # Create cache key
    cache_key = f"{config.REDIS_KEY_PREFIX}data:{tenant_id}:{start_time}:{end_time}:{limit}"
    
    try:
        # Try to get from cache
        cached_data = redis_client.get(cache_key)
        
        if cached_data:
            # Deserialize data
            df = pickle.loads(cached_data)
            tenant_logger.info(f"Retrieved {len(df)} records from cache")
            CACHE_OPERATIONS.labels(tenant=tenant_id, operation='get', status='hit').inc()
            return df
        
        # Cache miss, get from Elasticsearch
        CACHE_OPERATIONS.labels(tenant=tenant_id, operation='get', status='miss').inc()
        df = get_data_from_elasticsearch(tenant_id, start_time, end_time, limit)
        
        # Cache the result
        redis_client.setex(
            cache_key,
            config.REDIS_CACHE_TTL,
            pickle.dumps(df)
        )
        CACHE_OPERATIONS.labels(tenant=tenant_id, operation='set', status='success').inc()
        
        return df
    
    except Exception as e:
        tenant_logger.error(f"Error in cache operation: {str(e)}")
        CACHE_OPERATIONS.labels(tenant=tenant_id, operation='get', status='error').inc()
        
        # Fallback to direct Elasticsearch query
        return get_data_from_elasticsearch(tenant_id, start_time, end_time, limit)


# Train model from historical data
def train_model_from_history(tenant_id: str, algorithm: str = None) -> Dict:
    """Train a model using historical data from Elasticsearch"""
    tenant_logger = logging.LoggerAdapter(logger, {"tenant": tenant_id})
    
    if algorithm is None:
        algorithm = config.DEFAULT_ALGORITHM
    
    try:
        # Get historical data
        start_time = (datetime.now() - timedelta(days=config.TRAINING_WINDOW_DAYS)).isoformat()
        end_time = datetime.now().isoformat()
        
        tenant_logger.info(f"Training {algorithm} model with data from {start_time} to {end_time}")
        
        # Get data
        data = get_data_with_cache(tenant_id, start_time, end_time, config.MAX_TRAINING_SAMPLES)
        
        if len(data) < config.MIN_TRAINING_SAMPLES:
            tenant_logger.warning(f"Insufficient data for training: {len(data)} samples, minimum required: {config.MIN_TRAINING_SAMPLES}")
            raise ValueError(f"Insufficient data for training: {len(data)} samples")
        
        # Get model
        model = get_model(tenant_id, algorithm)
        
        # Train model
        metadata = model.fit(data)
        
        tenant_logger.info(f"Model trained successfully with {len(data)} samples")
        
        return metadata
    
    except Exception as e:
        tenant_logger.error(f"Error training model: {str(e)}")
        raise


# Schedule model retraining
def schedule_model_retraining():
    """Schedule periodic model retraining for all tenants"""
    tenants = get_all_tenants()
    
    for tenant_id in tenants:
        try:
            # Check if model exists and needs retraining
            for algorithm in ['seasonal_hybrid_esd', 'prophet', 'lstm']:
                try:
                    model = get_model(tenant_id, algorithm)
                    
                    if model.needs_retraining():
                        logger.info(f"Scheduling retraining for tenant {tenant_id}, algorithm {algorithm}")
                        train_model_from_history(tenant_id, algorithm)
                except Exception as e:
                    logger.error(f"Error retraining model for tenant {tenant_id}, algorithm {algorithm}: {str(e)}")
        
        except Exception as e:
            logger.error(f"Error scheduling retraining for tenant {tenant_id}: {str(e)}")


# Initialize scheduler
def init_scheduler():
    """Initialize the scheduler for periodic tasks"""
    global scheduler
    
    scheduler = BackgroundScheduler()
    
    # Schedule model retraining
    scheduler.add_job(
        schedule_model_retraining,
        'interval',
        hours=config.RETRAINING_INTERVAL_HOURS,
        id='model_retraining',
        replace_existing=True
    )
    
    # Start scheduler
    scheduler.start()
    logger.info("Scheduler started")
    
    return scheduler


# Tenant middleware
@app.before_request
def tenant_middleware():
    """Extract tenant information from request"""
    tenant_id = request.headers.get(config.TENANT_HEADER, config.DEFAULT_TENANT)
    
    # Store tenant in Flask g object
    g.tenant_id = tenant_id
    
    # Update logger context
    request.logger = logging.LoggerAdapter(logger, {"tenant": tenant_id})


# API routes

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    REQUESTS.labels(tenant=g.tenant_id, endpoint='/health', method='GET', status='success').inc()
    
    return jsonify({
        'status': 'UP',
        'timestamp': datetime.now().isoformat(),
        'version': os.environ.get('VERSION', '1.0.0')
    })


@app.route('/readiness', methods=['GET'])
def readiness_check():
    """Readiness check endpoint"""
    REQUESTS.labels(tenant=g.tenant_id, endpoint='/readiness', method='GET', status='success').inc()
    
    # Check Elasticsearch
    es_status = 'UP' if es_client and es_client.ping() else 'DOWN'
    
    # Check Redis
    redis_status = 'UP'
    if config.REDIS_ENABLED:
        try:
            if redis_client and redis_client.ping():
                redis_status = 'UP'
            else:
                redis_status = 'DOWN'
        except:
            redis_status = 'DOWN'
    
    # Check Kafka
    kafka_status = 'UP'
    if config.KAFKA_ENABLED:
        try:
            if kafka_producer:
                kafka_producer.flush()
                