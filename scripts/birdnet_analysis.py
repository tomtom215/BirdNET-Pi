import logging
import os
import os.path
import re
import signal
import sys
import threading
import time
import uuid
import json
import socket
import functools
import tempfile
from queue import Queue, Empty
from subprocess import CalledProcessError
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from logging.handlers import RotatingFileHandler
from threading import Lock, RLock, Event
import hashlib
import shutil
import random
import collections
from enum import Enum

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False  # Optional dependency for enhanced monitoring

try:
    from prometheus_client import Counter, Gauge, Histogram, start_http_server
    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False  # Optional dependency for metrics

import inotify.adapters
from inotify.constants import IN_CLOSE_WRITE

from server import load_global_model, run_analysis
from utils.helpers import get_settings, ParseFileName, get_wav_files, ANALYZING_NOW
from utils.reporting import extract_detection, summary, write_to_file, write_to_db, apprise, bird_weather, heartbeat, \
    update_json_file

# Error classification codes for consistent tracking
class ErrorCode(Enum):
    GENERAL_ERROR = "E001"
    CONFIGURATION_ERROR = "E002"
    FILE_ACCESS_ERROR = "E003"
    NETWORK_ERROR = "E004"
    DATABASE_ERROR = "E005"
    MODEL_ERROR = "E006"
    RESOURCE_ERROR = "E007"
    TIMEOUT_ERROR = "E008"
    CORRUPT_FILE_ERROR = "E009"
    SYSTEM_ERROR = "E010"
    DEPENDENCY_ERROR = "E011"

# Feature flags for staged rollout capability
FEATURE_FLAGS = {
    "enhanced_file_validation": True,
    "memory_optimized_processing": True,
    "jitter_backoff": True,
    "improved_circuit_breaker": True,
    "extended_health_checks": True,
    "graceful_degradation": True,
    "resource_monitoring": True
}

# Global variables
shutdown = False
shutdown_event = Event()  # Thread-safe event for signaling shutdown
force_timer = None  # Timer for forced shutdown
log = logging.getLogger(__name__)
SCRIPT_VERSION = "1.4.0"  # Updated version with production enhancements

# Thread synchronization
global_stats_lock = RLock()  # Reentrant lock for global stats access
processed_files_lock = Lock()  # Lock for processed_files set access
health_file_lock = Lock()  # Lock for health file updates
recovery_file_lock = Lock()  # Lock for recovery file updates

# Statistics tracking
global_stats = {
    "processed_count": 0,
    "error_count": 0,
    "skipped_count": 0,
    "start_time": 0,
    "backlog_size": 0,
    "circuit_breakers": {},
    "memory_usage": [],
    "corrupt_files_detected": 0,
    "timeouts": 0,
    "slow_analyses": 0,
    "file_size_distribution": {
        "0-1MB": 0,
        "1-10MB": 0,
        "10-50MB": 0,
        "50-100MB": 0,
        "100MB+": 0
    },
    # Resource monitoring thresholds with default values
    "thresholds": {
        "memory_critical": 90,  # Percentage
        "memory_warning": 80,   # Percentage
        "cpu_critical": 90,     # Percentage
        "cpu_warning": 80,      # Percentage
        "disk_critical": 95,    # Percentage
        "disk_warning": 85,     # Percentage
        "queue_size_critical": 900,  # Items
        "queue_size_warning": 700,   # Items
        "file_age_max": 30,     # Days
        "slow_analysis": 60     # Seconds
    },
    # Dependency status tracking
    "dependencies": {
        "model": {"status": "unknown", "last_check": 0},
        "database": {"status": "unknown", "last_check": 0},
        "filesystem": {"status": "unknown", "last_check": 0},
        "external_apis": {"status": "unknown", "last_check": 0}
    }
}

# Connection pool for database operations
db_connection_pool = None

# Prometheus metrics (if available)
if HAS_PROMETHEUS:
    # Counters
    PROCESSED_FILES = Counter('birdnet_processed_files_total', 'Total number of files processed')
    ERROR_COUNT = Counter('birdnet_errors_total', 'Total number of errors encountered', ['error_code'])
    SKIPPED_FILES = Counter('birdnet_skipped_files_total', 'Total number of files skipped')
    CORRUPT_FILES = Counter('birdnet_corrupt_files_total', 'Total number of corrupt files detected')
    TIMEOUT_COUNT = Counter('birdnet_timeouts_total', 'Total number of analysis timeouts')
    CIRCUIT_BREAKS = Counter('birdnet_circuit_breaks_total', 'Circuit breaker activations', ['service'])
    
    # Gauges
    QUEUE_SIZE = Gauge('birdnet_queue_size', 'Current size of the reporting queue')
    BACKLOG_SIZE = Gauge('birdnet_backlog_size', 'Current size of the file backlog')
    PROCESSED_FILES_SET_SIZE = Gauge('birdnet_processed_files_set_size', 'Size of the processed files tracking set')
    MEMORY_USAGE = Gauge('birdnet_memory_usage_percent', 'Current memory usage percentage')
    CPU_USAGE = Gauge('birdnet_cpu_usage_percent', 'Current CPU usage percentage')
    DISK_USAGE = Gauge('birdnet_disk_usage_percent', 'Current disk usage percentage')
    DEPENDENCY_STATUS = Gauge('birdnet_dependency_status', 'Status of external dependencies', ['dependency'])
    
    # Histograms
    FILE_SIZE = Histogram('birdnet_file_size_bytes', 'Size of processed files in bytes', buckets=(1024*1024, 10*1024*1024, 50*1024*1024, 100*1024*1024, float('inf')))
    ANALYSIS_DURATION = Histogram('birdnet_analysis_duration_seconds', 'Duration of analysis operations', buckets=(0.5, 1, 2, 5, 10, 30, 60, 120))


class CircuitBreakerState(Enum):
    """Enum for circuit breaker states"""
    CLOSED = "CLOSED"  # Normal operation
    OPEN = "OPEN"      # Service calls disabled
    HALF_OPEN = "HALF_OPEN"  # Testing if service is back


class CircuitBreaker:
    """Enhanced circuit breaker pattern implementation for external service calls
    
    Prevents cascading failures by temporarily disabling calls to failing services
    using a proper state machine approach.
    
    Args:
        name (str): Identifier for the circuit breaker
        failure_threshold (int): Number of failures before opening circuit
        reset_timeout (int): Seconds to wait before attempting reset
        half_open_max_calls (int): Maximum calls to allow in half-open state
    """
    def __init__(self, name, failure_threshold=5, reset_timeout=60, half_open_max_calls=1):
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.half_open_max_calls = half_open_max_calls
        self.failures = 0
        self.last_failure = 0
        self.last_state_change = time.time()
        self.state = CircuitBreakerState.CLOSED
        self.total_failures = 0
        self.total_successes = 0
        self.half_open_calls = 0
        self.lock = Lock()  # Add thread safety
    
    def can_execute(self):
        """Check if the protected operation can be executed
        
        Returns:
            bool: True if service call is allowed, False otherwise
        """
        with self.lock:
            if self.state == CircuitBreakerState.CLOSED:
                return True
            
            if self.state == CircuitBreakerState.OPEN:
                # Check if it's time to transition to half-open
                if time.time() - self.last_failure > self.reset_timeout:
                    self._transition_to(CircuitBreakerState.HALF_OPEN)
                    self.half_open_calls = 0
                    return True
                return False
                
            if self.state == CircuitBreakerState.HALF_OPEN:
                # Allow limited calls in half-open state
                if self.half_open_calls < self.half_open_max_calls:
                    self.half_open_calls += 1
                    return True
                return False
                
            # Default safety - shouldn't reach here
            return False
    
    def record_failure(self):
        """Record a failure and potentially open the circuit"""
        with self.lock:
            self.total_failures += 1
            self.last_failure = time.time()
            
            if self.state == CircuitBreakerState.CLOSED:
                self.failures += 1
                if self.failures >= self.failure_threshold:
                    self._transition_to(CircuitBreakerState.OPEN)
                    # Update metrics if available
                    if HAS_PROMETHEUS:
                        CIRCUIT_BREAKS.labels(service=self.name).inc()
                    
            elif self.state == CircuitBreakerState.HALF_OPEN:
                # Any failure in half-open state immediately opens the circuit
                self._transition_to(CircuitBreakerState.OPEN)
                if HAS_PROMETHEUS:
                    CIRCUIT_BREAKS.labels(service=self.name).inc()
                
    def record_success(self):
        """Record a success and potentially close the circuit"""
        with self.lock:
            self.total_successes += 1
            
            if self.state == CircuitBreakerState.HALF_OPEN:
                # Success in half-open state - if we've had enough, close the circuit
                if self.half_open_calls >= self.half_open_max_calls:
                    self._transition_to(CircuitBreakerState.CLOSED)
                    
            elif self.state == CircuitBreakerState.CLOSED:
                # Reset failure count on success in closed state
                self.failures = 0
                
    def _transition_to(self, new_state):
        """Handle state transitions with proper logging
        
        Args:
            new_state (CircuitBreakerState): The new state to transition to
        """
        old_state = self.state
        if old_state != new_state:
            self.state = new_state
            self.last_state_change = time.time()
            log.info(f"Circuit breaker for {self.name} transitioned from {old_state.value} to {new_state.value}")
            
            # Reset appropriate counters based on new state
            if new_state == CircuitBreakerState.CLOSED:
                self.failures = 0
            elif new_state == CircuitBreakerState.HALF_OPEN:
                self.half_open_calls = 0
                
    def get_stats(self):
        """Get statistics about the circuit breaker
        
        Returns:
            dict: Statistics about successes and failures
        """
        with self.lock:
            return {
                "name": self.name,
                "state": self.state.value,
                "failures": self.failures,
                "total_failures": self.total_failures,
                "total_successes": self.total_successes,
                "success_rate": self._calculate_success_rate(),
                "time_in_state": round(time.time() - self.last_state_change, 1)
            }
    
    def _calculate_success_rate(self):
        """Calculate success rate
        
        Returns:
            float: Success rate as percentage, or None if no operations
        """
        total = self.total_successes + self.total_failures
        if total == 0:
            return None
        return round((self.total_successes / total) * 100, 1)


class DBConnectionPool:
    """Enhanced connection pool for database operations
    
    This provides a thread-safe way to manage and reuse database connections
    with enhanced monitoring and health checking.
    """
    def __init__(self, max_connections=10, connection_timeout=30, validation_interval=300):
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout
        self.validation_interval = validation_interval  # How often to validate idle connections
        self.pool = Queue(maxsize=max_connections)
        self.active_connections = 0
        self.lock = Lock()
        self.pool_initialized = False
        self.last_validation = 0
        self.stats = {
            "created_connections": 0,
            "closed_connections": 0,
            "max_active_connections": 0,
            "connection_errors": 0,
            "validation_failures": 0
        }
        
    def initialize(self):
        """Initialize the connection pool (lazy initialization)"""
        if self.pool_initialized:
            return
        with self.lock:
            if not self.pool_initialized:
                # Create initial connections
                for _ in range(min(3, self.max_connections)):
                    try:
                        connection = self._create_connection()
                        self.pool.put(connection)
                        self.stats["created_connections"] += 1
                    except Exception as e:
                        self.stats["connection_errors"] += 1
                        log.warning(f"Failed to create initial DB connection: {e}")
                self.pool_initialized = True
                log.info(f"Database connection pool initialized with {self.pool.qsize()} connections")
                
    def get_connection(self):
        """Get a connection from the pool or create a new one
        
        Returns:
            connection: Database connection object
        """
        # Ensure pool is initialized
        if not self.pool_initialized:
            self.initialize()
            
        # Check if idle connections need validation
        self._validate_idle_connections()
            
        # Try to get a connection from the pool
        try:
            connection = self.pool.get(block=True, timeout=self.connection_timeout)
            # Validate connection before returning
            if not self._validate_connection(connection):
                connection = self._create_connection()
                self.stats["validation_failures"] += 1
                self.stats["created_connections"] += 1
            return connection
        except Empty:
            # If pool is empty, create new connection if under limit
            with self.lock:
                if self.active_connections < self.max_connections:
                    self.active_connections += 1
                    self.stats["max_active_connections"] = max(
                        self.stats["max_active_connections"], 
                        self.active_connections
                    )
                    try:
                        conn = self._create_connection()
                        self.stats["created_connections"] += 1
                        return conn
                    except Exception as e:
                        self.active_connections -= 1
                        self.stats["connection_errors"] += 1
                        raise Exception(f"Failed to create DB connection: {e}")
                else:
                    raise Exception("Maximum database connections reached")
    
    def release_connection(self, connection):
        """Return a connection to the pool
        
        Args:
            connection: Database connection to return to the pool
        """
        if connection is None:
            return
            
        # Validate connection health before returning to pool
        if self._validate_connection(connection):
            self.pool.put(connection)
        else:
            # If connection is not valid, close and create a new one
            self._close_connection(connection)
            self.stats["validation_failures"] += 1
            
            try:
                new_connection = self._create_connection()
                self.pool.put(new_connection)
                self.stats["created_connections"] += 1
            except Exception as e:
                with self.lock:
                    self.active_connections -= 1
                self.stats["connection_errors"] += 1
                log.warning(f"Failed to create replacement connection: {e}")
    
    def close_all(self):
        """Close all connections in the pool"""
        # Clear the pool
        with self.lock:
            while not self.pool.empty():
                try:
                    connection = self.pool.get(block=False)
                    self._close_connection(connection)
                except Empty:
                    break
            self.active_connections = 0
            self.pool_initialized = False
        log.info("All database connections closed")
    
    def _validate_idle_connections(self):
        """Periodically validate idle connections to ensure they are still alive"""
        current_time = time.time()
        if current_time - self.last_validation > self.validation_interval:
            with self.lock:
                if current_time - self.last_validation > self.validation_interval:
                    self.last_validation = current_time
                    
                    # Only validate if we have idle connections
                    if not self.pool.empty():
                        log.debug(f"Validating {self.pool.qsize()} idle database connections")
                        
                        # Extract all connections from the pool
                        connections = []
                        while not self.pool.empty():
                            try:
                                connections.append(self.pool.get(block=False))
                            except Empty:
                                break
                        
                        # Validate and return valid connections to the pool
                        valid_count = 0
                        for conn in connections:
                            if self._validate_connection(conn):
                                self.pool.put(conn)
                                valid_count += 1
                            else:
                                self._close_connection(conn)
                                self.stats["validation_failures"] += 1
                        
                        # Log validation results
                        if len(connections) > 0:
                            log.debug(f"Connection validation: {valid_count}/{len(connections)} valid")
                    
    def _create_connection(self):
        """Create a new database connection
        
        This method must be implemented by the specific database adapter
        
        Returns:
            connection: New database connection
        """
        # Placeholder for actual implementation (replace with your DB connection code)
        # Example for SQLite
        try:
            import sqlite3
            # Get DB path from settings
            conf = get_settings()
            db_path = conf.get('DB_PATH', '/var/lib/birdnet/birds.db')
            
            # Ensure directory exists
            db_dir = os.path.dirname(db_path)
            if not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
                
            connection = sqlite3.connect(db_path, timeout=30)
            
            # Enable foreign keys and set pragmas for better performance and safety
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys = ON")
            cursor.execute("PRAGMA journal_mode = WAL")  # Write-ahead logging
            cursor.execute("PRAGMA synchronous = NORMAL")  # Safer than OFF, faster than FULL
            cursor.execute("SELECT 1")  # Test query
            cursor.close()
            
            return connection
        except ImportError:
            log.warning("SQLite3 not available, using dummy connection")
            # Dummy connection for testing
            class DummyConnection:
                def close(self):
                    pass
                def cursor(self):
                    class DummyCursor:
                        def execute(self, query):
                            pass
                        def close(self):
                            pass
                    return DummyCursor()
            return DummyConnection()
            
    def _validate_connection(self, connection):
        """Validate that a connection is still active and usable
        
        Args:
            connection: Database connection to validate
            
        Returns:
            bool: True if connection is valid, False otherwise
        """
        # Placeholder for actual implementation
        # For example, with SQLite:
        try:
            if hasattr(connection, 'cursor'):
                cursor = connection.cursor()
                cursor.execute("SELECT 1")
                cursor.close()
                return True
            return True  # Default to true for dummy connections
        except Exception:
            return False
            
    def _close_connection(self, connection):
        """Close a database connection
        
        Args:
            connection: Database connection to close
        """
        try:
            if hasattr(connection, 'close'):
                connection.close()
                self.stats["closed_connections"] += 1
        except Exception as e:
            log.warning(f"Error closing database connection: {e}")
            
    def get_stats(self):
        """Get statistics about the connection pool
        
        Returns:
            dict: Connection pool statistics
        """
        with self.lock:
            stats_copy = self.stats.copy()
            stats_copy.update({
                "pool_size": self.pool.qsize(),
                "active_connections": self.active_connections,
                "initialized": self.pool_initialized,
                "max_connections": self.max_connections
            })
            return stats_copy


def add_jitter(delay, jitter_factor=0.25):
    """Add random jitter to delay times to prevent thundering herds
    
    Args:
        delay (float): Base delay time in seconds
        jitter_factor (float): How much jitter to add (0.0-1.0)
        
    Returns:
        float: Delay with jitter added
    """
    # Ensure jitter factor is reasonable
    jitter_factor = max(0.0, min(1.0, jitter_factor))
    
    # Calculate jitter range
    jitter_range = delay * jitter_factor
    
    # Add random jitter
    return delay + random.uniform(-jitter_range, jitter_range)


def retry(max_attempts=3, delay=1.0, backoff=2.0, jitter=True, exceptions=(Exception,), logger=None):
    """Retry decorator with exponential backoff and jitter
    
    Args:
        max_attempts: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        backoff: Backoff multiplier (e.g. value of 2 will double the delay each retry)
        jitter: Whether to add jitter to delay times
        exceptions: Tuple of exceptions to catch and retry on
        logger: Logger to use for logging retries
    
    Returns:
        Decorated function
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            _logger = logger or log
            _delay = delay
            last_exception = None
            
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts:
                        # Add jitter to avoid thundering herd
                        actual_delay = add_jitter(_delay, 0.25) if jitter and FEATURE_FLAGS["jitter_backoff"] else _delay
                        
                        _logger.warning(
                            f"Retry {attempt}/{max_attempts} for {func.__name__} "
                            f"after error: {str(e)}. Retrying in {actual_delay:.1f}s"
                        )
                        time.sleep(actual_delay)
                        _delay *= backoff
                    else:
                        break
                        
            # If we get here, all retries failed
            if last_exception:
                _logger.error(f"All {max_attempts} retries failed for {func.__name__}")
                raise last_exception
                
        return wrapper
    return decorator


def sig_handler(sig_num, curr_stack_frame):
    """Enhanced signal handler with graceful shutdown timeout
    
    Args:
        sig_num: Signal number
        curr_stack_frame: Current stack frame
    """
    global shutdown, force_timer, shutdown_event
    log.info(f'Caught shutdown signal {sig_num}, initiating graceful shutdown')
    shutdown = True
    shutdown_event.set()  # Signal all waiting threads
    
    # Cancel existing timer if there is one
    if force_timer and force_timer.is_alive():
        force_timer.cancel()
    
    # Set a timeout for graceful shutdown
    def force_exit():
        log.error("Graceful shutdown timed out. Forcing exit.")
        # Attempt to log final state before exit
        try:
            update_health_file(
                get_settings().get('HEALTH_CHECK_FILE', '/tmp/birdnet_health'),
                "forced_shutdown",
                {"reason": "shutdown timeout"}
            )
        except Exception:
            pass  # Don't let errors in final logging prevent shutdown
        sys.exit(1)
    
    # Schedule force exit after timeout
    force_timer = threading.Timer(60, force_exit)
    force_timer.daemon = True
    force_timer.start()


def validate_configuration(conf):
    """Validate configuration and set defaults
    
    Args:
        conf (dict): Configuration dictionary
        
    Returns:
        dict: Validated configuration with defaults
        
    Raises:
        ValueError: If required configuration is missing or invalid
    """
    required_keys = ['RECS_DIR']
    for key in required_keys:
        if key not in conf:
            raise ValueError(f"Missing required configuration: {key}")
    
    # Validate directory paths
    dirs_to_check = [
        conf['RECS_DIR'],
        conf.get('STREAM_DATA_DIR', os.path.join(conf['RECS_DIR'], 'StreamData'))
    ]
    
    for directory in dirs_to_check:
        if not os.path.isdir(directory):
            log.warning(f"Directory does not exist: {directory}")
            try:
                os.makedirs(directory, exist_ok=True)
                log.info(f"Created directory: {directory}")
            except Exception as e:
                raise ValueError(f"Could not create directory {directory}: {e}")
    
    # Validate write permissions for critical directories
    dirs_to_validate_write = dirs_to_check + [
        conf.get('RECOVERY_DIR', '/tmp/birdnet_recovery'),
        os.path.dirname(conf.get('HEALTH_CHECK_FILE', '/tmp/birdnet_health')),
        os.path.dirname(conf.get('RECOVERY_FILE', '/tmp/birdnet_recovery.json'))
    ]
    
    for directory in dirs_to_validate_write:
        if directory and not os.path.exists(directory):
            try:
                os.makedirs(directory, exist_ok=True)
            except Exception as e:
                log.warning(f"Could not create directory {directory}: {e}")
                
        if directory and os.path.exists(directory):
            # Check write permissions by trying to create a test file
            test_file = os.path.join(directory, f".write_test_{uuid.uuid4().hex}")
            try:
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
            except (IOError, OSError) as e:
                raise ValueError(f"No write permission for directory {directory}: {e}")
    
    # Set defaults for new configurations to ensure backward compatibility
    defaults = {
        'RECORDING_LENGTH': 30,
        'MAX_QUEUE_SIZE': 1000,
        'MAX_WORKERS': 4,
        'HEALTH_INTERVAL': 60,
        'STATE_SAVE_INTERVAL': 300,
        'DB_FAILURE_THRESHOLD': 3,
        'DB_RESET_TIMEOUT': 300,
        'APPRISE_FAILURE_THRESHOLD': 3,
        'APPRISE_RESET_TIMEOUT': 300,
        'WEATHER_FAILURE_THRESHOLD': 3,
        'WEATHER_RESET_TIMEOUT': 300,
        'THROTTLE_DELAY': 0.1,
        'OVERLOAD_DELAY': 5.0,
        'ANALYSIS_THROTTLE_DELAY': 2.0,
        'QUEUE_TIMEOUT': 30.0,
        'MAX_REPORTING_RETRIES': 3,
        'RETRY_DELAY': 2.0,
        'STATUS_LOG_INTERVAL': 300,
        'THREAD_JOIN_TIMEOUT': 60,
        'QUEUE_JOIN_TIMEOUT': 10,
        'LOG_LEVEL': 'INFO',
        'LOG_FORMAT': 'standard',
        'LOG_TO_FILE': 'false',
        'RECOVERY_DIR': '/tmp/birdnet_recovery',
        'RECOVERY_FILE': '/tmp/birdnet_recovery.json',
        'HEALTH_CHECK_FILE': '/tmp/birdnet_health',
        'LEGACY_MODE': 'false',  # Enable backward compatibility mode
        'MAX_MEMORY_PERCENT': 85,  # Maximum memory usage percentage
        'BACKLOG_CHUNK_SIZE': 100,  # Size of backlog chunks for processing
        'PROCESSED_FILES_MEMORY_LIMIT': 10000,  # Maximum number of processed files to keep in memory
        'FILE_SIZE_WARNING_THRESHOLD_MB': 100,  # Warn for files larger than this in MB
        'PATH_VALIDATION_STRICT': 'true',  # Enable strict path validation
        'DB_MAX_CONNECTIONS': 10,  # Maximum database connections in pool
        'DB_CONNECTION_TIMEOUT': 30,  # Timeout for database connection operations
        'ANALYSIS_TIMEOUT': 300,  # Timeout for analysis operations in seconds
        'ENABLE_METRICS': 'false',  # Enable Prometheus metrics
        'METRICS_PORT': 9090,  # Port for Prometheus metrics server
        'MAX_FILE_AGE_DAYS': 30,  # Maximum age of files to process
        'CORRUPT_FILE_DIR': '',  # Directory to move corrupt files to (empty = delete)
        'STATS_RETENTION_COUNT': 100,  # Number of memory/CPU readings to retain
        'CPU_WARNING_THRESHOLD': 80,  # CPU usage warning threshold percentage
        'DISK_WARNING_THRESHOLD': 90,  # Disk usage warning threshold percentage
        'HALF_OPEN_MAX_CALLS': 3,  # Number of calls to allow in half-open circuit state
        'DB_VALIDATION_INTERVAL': 300,  # How often to validate idle connections (seconds)
        'DEPENDENCY_CHECK_INTERVAL': 600,  # How often to check dependencies (seconds)
        'JITTER_FACTOR': 0.25,  # How much jitter to add to delay times (percentage)
        'TESTING_MODE': 'false',  # Enable testing mode with hooks
        'GRACEFUL_DEGRADATION': 'true',  # Enable graceful degradation features
        'MEMORY_OPTIMIZED': 'true',  # Enable memory optimization features
        'MAX_WAV_HEADER_SIZE': 256,  # Maximum bytes to read for WAV validation
        'WAV_MINIMUM_HEADER_SIZE': 44,  # Minimum header size for valid WAV file
        'SHUTDOWN_TIMEOUT': 60,  # Maximum seconds to wait for graceful shutdown
        'WORKER_THREAD_PRIORITY': 0,  # Thread priority adjustment (0=normal, negative=higher)
        'ENABLE_SELF_HEALING': 'true',  # Enable automatic recovery features
        'CRITICAL_DEPENDENCIES': 'model,filesystem',  # Comma-separated list of critical dependencies
        'NONCRITICAL_DEPENDENCIES': 'database,external_apis',  # Comma-separated list of non-critical dependencies
        'FAST_FAILURE_MODE': 'false',  # Fail fast on critical dependency failure
    }
    
    # Apply defaults
    for key, value in defaults.items():
        if key not in conf:
            conf[key] = value
    
    # Convert string values to appropriate types
    conf_with_types = conf.copy()
    for key, value in conf.items():
        if key in defaults and not isinstance(value, type(defaults[key])):
            try:
                if isinstance(defaults[key], bool) or key.endswith('_STRICT') or key.startswith('LEGACY_') or key.startswith('ENABLE_'):
                    conf_with_types[key] = str(value).lower() == 'true'
                elif isinstance(defaults[key], int):
                    conf_with_types[key] = int(value)
                elif isinstance(defaults[key], float):
                    conf_with_types[key] = float(value)
            except (ValueError, TypeError) as e:
                log.warning(f"Could not convert configuration {key}={value} to {type(defaults[key]).__name__}: {e}")
    
    # Parse comma-separated values into lists
    for key in ['CRITICAL_DEPENDENCIES', 'NONCRITICAL_DEPENDENCIES']:
        if isinstance(conf_with_types.get(key, ''), str):
            conf_with_types[key] = [x.strip() for x in conf_with_types[key].split(',') if x.strip()]
    
    # Load resource monitoring thresholds from configuration
    with global_stats_lock:
        thresholds = global_stats.get('thresholds', {})
        # Map config values to threshold names
        threshold_map = {
            'MAX_MEMORY_PERCENT': 'memory_critical',
            'CPU_WARNING_THRESHOLD': 'cpu_warning',
            'DISK_WARNING_THRESHOLD': 'disk_warning',
            'MAX_FILE_AGE_DAYS': 'file_age_max'
        }
        
        # Update thresholds from configuration
        for config_key, threshold_key in threshold_map.items():
            if config_key in conf_with_types:
                thresholds[threshold_key] = conf_with_types[config_key]
                
        # Derived thresholds
        if 'memory_critical' in thresholds:
            thresholds['memory_warning'] = int(thresholds['memory_critical'] * 0.9)
        if 'cpu_warning' in thresholds:
            thresholds['cpu_critical'] = min(thresholds['cpu_warning'] + 10, 99)
        if 'disk_warning' in thresholds:
            thresholds['disk_critical'] = min(thresholds['disk_warning'] + 5, 99)
            
        # Queue size thresholds
        thresholds['queue_size_critical'] = int(conf_with_types.get('MAX_QUEUE_SIZE', 1000) * 0.9)
        thresholds['queue_size_warning'] = int(conf_with_types.get('MAX_QUEUE_SIZE', 1000) * 0.7)
        
        # Analysis thresholds
        thresholds['slow_analysis'] = conf_with_types.get('ANALYSIS_TIMEOUT', 300) / 5  # 20% of timeout
        
        global_stats['thresholds'] = thresholds
    
    return conf_with_types


def sanitize_path(path, base_dir=None, strict=True):
    """Sanitize file paths to prevent path traversal
    
    Args:
        path (str): File path to sanitize
        base_dir (str, optional): Base directory to restrict access to
        strict (bool): Whether to enforce strict path validation
        
    Returns:
        str: Sanitized path, or None if path is invalid
    """
    # Normalize path and ensure it's within allowed directory
    if not path:
        return None
        
    try:
        # First convert to absolute path if base_dir is provided
        if base_dir:
            if not os.path.isabs(path):
                path = os.path.join(base_dir, path)
            
        # Normalize the path
        norm_path = os.path.normpath(path)
        
        # Ensure absolute paths stay within base_dir
        if base_dir and os.path.isabs(norm_path):
            base_dir = os.path.abspath(base_dir)
            rel_path = os.path.relpath(norm_path, base_dir)
            
            # Check if path attempts to escape base directory
            if rel_path.startswith('..') and strict:
                log.warning(f"Path {path} attempts to escape base directory {base_dir}")
                return None
        
        # Check for other dangerous patterns
        if '..' in norm_path.split(os.sep) and strict:
            log.warning(f"Path contains parent directory references: {path}")
            return None
            
        # Additional security checks
        if any(c in norm_path for c in ['*', '?', '[', ']']):
            log.warning(f"Path contains glob patterns: {path}")
            return None
            
        return norm_path
        
    except Exception as e:
        log.warning(f"Error sanitizing path {path}: {e}")
        return None


def is_system_overloaded(conf):
    """Check if system resources are overloaded
    
    Args:
        conf (dict): Configuration settings
        
    Returns:
        bool: True if system is overloaded, False otherwise
        dict: Resource metrics
    """
    # Get thresholds from global stats
    with global_stats_lock:
        thresholds = global_stats.get('thresholds', {})
    
    # Default thresholds if not in global stats
    max_memory_percent = thresholds.get('memory_critical', conf.get('MAX_MEMORY_PERCENT', 85))
    cpu_warning_threshold = thresholds.get('cpu_warning', conf.get('CPU_WARNING_THRESHOLD', 80))
    disk_warning_threshold = thresholds.get('disk_warning', conf.get('DISK_WARNING_THRESHOLD', 90))
    
    # Initialize resource metrics
    metrics = {
        'cpu_percent': None,
        'memory_percent': None,
        'disk_percent': None,
        'is_overloaded': False,
        'reason': None
    }
    
    # Check load
    try:
        if HAS_PSUTIL:
            # Use psutil if available for better resource monitoring
            metrics['cpu_percent'] = psutil.cpu_percent(interval=0.1)
            metrics['memory_percent'] = psutil.virtual_memory().percent
            metrics['disk_percent'] = psutil.disk_usage('/').percent
            
            # Update metrics if enabled
            if HAS_PROMETHEUS:
                MEMORY_USAGE.set(metrics['memory_percent'])
                CPU_USAGE.set(metrics['cpu_percent'])
                DISK_USAGE.set(metrics['disk_percent'])
            
            # Add memory info to global stats with thread safety
            with global_stats_lock:
                if 'memory_usage' not in global_stats:
                    global_stats['memory_usage'] = []
                
                # Keep last readings based on configured retention
                memory_data = {
                    'timestamp': time.time(),
                    'memory_percent': metrics['memory_percent'],
                    'cpu_percent': metrics['cpu_percent'],
                    'disk_percent': metrics['disk_percent']
                }
                
                global_stats['memory_usage'].append(memory_data)
                retention = conf.get('STATS_RETENTION_COUNT', 100)
                if len(global_stats['memory_usage']) > retention:
                    global_stats['memory_usage'] = global_stats['memory_usage'][-retention:]
            
            # Log warnings if resources are high but not critical
            if metrics['memory_percent'] > max_memory_percent * 0.9 and metrics['memory_percent'] <= max_memory_percent:
                log.warning(f"Memory usage approaching threshold: {metrics['memory_percent']:.1f}%")
            if metrics['cpu_percent'] > cpu_warning_threshold * 0.9 and metrics['cpu_percent'] <= cpu_warning_threshold:
                log.warning(f"CPU usage approaching threshold: {metrics['cpu_percent']:.1f}%")
            if metrics['disk_percent'] > disk_warning_threshold * 0.9 and metrics['disk_percent'] <= disk_warning_threshold:
                log.warning(f"Disk usage approaching threshold: {metrics['disk_percent']:.1f}%")
            
            # Check if system is overloaded and identify reason
            if metrics['cpu_percent'] > cpu_warning_threshold:
                metrics['is_overloaded'] = True
                metrics['reason'] = f"CPU usage {metrics['cpu_percent']:.1f}% exceeds threshold {cpu_warning_threshold}%"
            elif metrics['memory_percent'] > max_memory_percent:
                metrics['is_overloaded'] = True
                metrics['reason'] = f"Memory usage {metrics['memory_percent']:.1f}% exceeds threshold {max_memory_percent}%"
            elif metrics['disk_percent'] > disk_warning_threshold:
                metrics['is_overloaded'] = True
                metrics['reason'] = f"Disk usage {metrics['disk_percent']:.1f}% exceeds threshold {disk_warning_threshold}%"
            
            if metrics['is_overloaded']:
                log.warning(f"System overloaded: {metrics['reason']}")
                
        else:
            # Fallback to basic load average check
            load = os.getloadavg()[0]
            cpu_count = os.cpu_count() or 1
            metrics['cpu_percent'] = (load / cpu_count) * 100
            metrics['is_overloaded'] = metrics['cpu_percent'] > cpu_warning_threshold
            
            if metrics['is_overloaded']:
                metrics['reason'] = f"System load {load:.1f} exceeds threshold {cpu_count * 0.8:.1f}"
                log.warning(f"System load high: {load:.1f} (threshold: {cpu_count * 0.8:.1f})")
    except Exception as e:
        log.warning(f"Error checking system load: {e}")
        
    return metrics['is_overloaded'], metrics


def atomic_write_json(data, filepath):
    """Write JSON data to a file atomically
    
    Creates a temporary file and renames it to ensure atomic write operations
    
    Args:
        data: Data to write to file (must be JSON serializable)
        filepath: Target file path
    """
    # Ensure directory exists
    directory = os.path.dirname(filepath)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    
    # Create a temporary file in the same directory
    fd, temp_filepath = tempfile.mkstemp(prefix=os.path.basename(filepath), 
                                        dir=directory,
                                        suffix='.tmp')
    
    success = False
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())  # Ensure data is written to disk
            
        # Perform atomic rename
        os.replace(temp_filepath, filepath)
        success = True
    except Exception as e:
        # Clean up temp file if still exists
        if os.path.exists(temp_filepath):
            try:
                os.remove(temp_filepath)
            except Exception:
                pass
        raise e
    finally:
        # Clean up temp file if not successfully renamed
        if not success and os.path.exists(temp_filepath):
            try:
                os.remove(temp_filepath)
            except Exception:
                pass


def save_processing_state(processed_files, queue_items, recovery_file):
    """Save current processing state for recovery
    
    Args:
        processed_files (OrderedDict): OrderedDict of processed file paths
        queue_items (list): Current queue items for recovery
        recovery_file (str): Path to recovery file
    """
    try:
        # Create directory if needed
        os.makedirs(os.path.dirname(recovery_file), exist_ok=True)
        
        # Convert processed_files OrderedDict to list with thread safety
        with processed_files_lock:
            processed_list = list(processed_files.keys())
            # Keep only most recent files if needed - OrderedDict preserves order
            if len(processed_list) > 1000:
                processed_list = processed_list[-1000:]
        
        # Gather stats with thread safety
        with global_stats_lock:
            stats_copy = {
                'processed_count': global_stats.get('processed_count', 0),
                'error_count': global_stats.get('error_count', 0),
                'skipped_count': global_stats.get('skipped_count', 0),
                'corrupt_files_detected': global_stats.get('corrupt_files_detected', 0),
                'timeouts': global_stats.get('timeouts', 0),
                'uptime': int(time.time() - global_stats.get('start_time', time.time()))
            }
        
        # Use thread-safe atomic write
        with recovery_file_lock:
            atomic_write_json({
                'timestamp': time.time(),
                'version': SCRIPT_VERSION,
                'processed_files': processed_list,
                'queue_items': queue_items,
                'stats': stats_copy
            }, recovery_file)
    except Exception as e:
        log.warning(f"Failed to save recovery state: {e}")


def load_processing_state(recovery_file):
    """Load processing state from recovery file
    
    Args:
        recovery_file (str): Path to recovery file
        
    Returns:
        tuple: (processed_files, queue_items)
    """
    try:
        if os.path.exists(recovery_file):
            with open(recovery_file, 'r') as f:
                state = json.load(f)
            
            # Version check for compatibility
            state_version = state.get('version', '0.0.0')
            if state_version != SCRIPT_VERSION:
                log.warning(f"Recovery state version mismatch: {state_version} != {SCRIPT_VERSION}")
                # Still try to use the data, just log the warning
                
            # Load stats with thread safety
            if 'stats' in state:
                with global_stats_lock:
                    for key, value in state['stats'].items():
                        global_stats[key] = value
            
            # Convert list back to OrderedDict with timestamps
            processed_files = collections.OrderedDict()
            for file_path in state.get('processed_files', []):
                processed_files[file_path] = time.time()
                
            log.info(f"Loaded recovery state from {recovery_file}: {len(processed_files)} processed files")
            return processed_files, state.get('queue_items', [])
    except Exception as e:
        log.warning(f"Failed to load recovery state: {e}")
    
    return collections.OrderedDict(), []


def log_error_with_context(e, context=None, error_code=ErrorCode.GENERAL_ERROR):
    """Log error with additional context information
    
    Args:
        e (Exception): Exception to log
        context (dict, optional): Additional context information
        error_code (ErrorCode): Classification code for the error
        
    Returns:
        str: Error ID for reference
    """
    error_id = str(uuid.uuid4())[:8]  # Generate short ID for error tracking
    
    # Use the enum value as the error code string
    error_code_str = error_code.value if isinstance(error_code, ErrorCode) else ErrorCode.GENERAL_ERROR.value
    
    # Gather system information
    system_info = {
        'error_id': error_id,
        'error_code': error_code_str,
        'hostname': socket.gethostname(),
        'pid': os.getpid(),
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
        'script_version': SCRIPT_VERSION
    }
    
    # Add memory info if psutil is available
    if HAS_PSUTIL:
        try:
            process = psutil.Process(os.getpid())
            system_info['memory_usage_mb'] = process.memory_info().rss / 1024 / 1024  # MB
            system_info['cpu_percent'] = process.cpu_percent(interval=0.1)
            system_info['open_files'] = len(process.open_files())
            system_info['threads'] = process.num_threads()
        except Exception as psutil_err:
            system_info['psutil_error'] = str(psutil_err)
    
    # Format context information
    context_str = ""
    if context:
        system_info.update(context)
        context_str = ", ".join(f"{k}={v}" for k, v in context.items())
    
    # Get full traceback
    import traceback
    tb = traceback.format_exc()
    
    # Log the error with all information
    log.error(f"Error[{error_id}][{error_code_str}] {e.__class__.__name__}: {str(e)} | {context_str}\n{tb}")
    
    # Update error counter with thread safety
    with global_stats_lock:
        global_stats['error_count'] = global_stats.get('error_count', 0) + 1
    
    # Update metrics if available
    if HAS_PROMETHEUS:
        ERROR_COUNT.labels(error_code=error_code_str).inc()
    
    # Save error details to file for later analysis
    try:
        error_log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'errors')
        os.makedirs(error_log_dir, exist_ok=True)
        
        error_file = os.path.join(error_log_dir, f"error_{error_id}_{int(time.time())}.json")
        atomic_write_json({
            'error': {
                'type': e.__class__.__name__,
                'message': str(e),
                'code': error_code_str,
                'traceback': tb
            },
            'context': system_info
        }, error_file)
    except Exception as log_err:
        log.warning(f"Could not save detailed error log: {log_err}")
    
    return error_id


def update_health_file(health_file, status, extra_info=None):
    """Update health check file with current status
    
    Args:
        health_file (str): Path to health file
        status (str): Current status (running, stopping, etc.)
        extra_info (dict, optional): Additional information to include
    """
    try:
        with health_file_lock:  # Thread safety for health file updates
            health_dir = os.path.dirname(health_file)
            # First check if directory exists before trying to create it
            if not os.path.exists(health_dir):
                try:
                    os.makedirs(health_dir, exist_ok=True)
                except Exception as e:
                    log.warning(f"Could not create health directory {health_dir}: {e}")
                    # Try using /tmp as fallback
                    health_file = f"/tmp/birdnet_health_{os.getpid()}"
            
            # Gather current stats with thread safety
            with global_stats_lock:
                stats_copy = {
                    "processed_count": global_stats.get("processed_count", 0),
                    "error_count": global_stats.get("error_count", 0),
                    "skipped_count": global_stats.get("skipped_count", 0),
                    "corrupt_files_detected": global_stats.get("corrupt_files_detected", 0),
                    "timeouts": global_stats.get("timeouts", 0),
                    "slow_analyses": global_stats.get("slow_analyses", 0),
                    "thresholds": global_stats.get("thresholds", {}),
                    "dependencies": global_stats.get("dependencies", {})
                }
            
            health_data = {
                "timestamp": time.time(),
                "status": status,
                "hostname": socket.gethostname(),
                "pid": os.getpid(),
                "version": SCRIPT_VERSION,
                "uptime": int(time.time() - global_stats.get('start_time', time.time())),
                "feature_flags": FEATURE_FLAGS
            }
            
            # Add system stats if psutil is available
            if HAS_PSUTIL:
                try:
                    memory_percent = psutil.virtual_memory().percent
                    cpu_percent = psutil.cpu_percent(interval=0.1)
                    disk_percent = psutil.disk_usage('/').percent
                    
                    health_data.update({
                        "cpu_percent": cpu_percent,
                        "memory_percent": memory_percent,
                        "disk_percent": disk_percent,
                        "process_memory_mb": psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024
                    })
                    
                    # Add warning flags
                    health_data["memory_warning"] = memory_percent > stats_copy["thresholds"].get("memory_warning", 80)
                    health_data["memory_critical"] = memory_percent > stats_copy["thresholds"].get("memory_critical", 90)
                    health_data["cpu_warning"] = cpu_percent > stats_copy["thresholds"].get("cpu_warning", 80)
                    health_data["cpu_critical"] = cpu_percent > stats_copy["thresholds"].get("cpu_critical", 90)
                    health_data["disk_warning"] = disk_percent > stats_copy["thresholds"].get("disk_warning", 85)
                    health_data["disk_critical"] = disk_percent > stats_copy["thresholds"].get("disk_critical", 95)
                    
                except Exception as e:
                    health_data["stat_error"] = str(e)
            
            # Add stats from global stats
            health_data.update(stats_copy)
            
            # Add circuit breaker stats
            if 'circuit_breakers' in global_stats:
                health_data["circuit_breakers"] = global_stats['circuit_breakers']
            
            # Add extra info
            if extra_info:
                health_data.update(extra_info)
                
            # Use atomic write to prevent partial reads
            atomic_write_json(health_data, health_file)
            
    except Exception as e:
        log.warning(f"Failed to update health check: {e}")


def validate_wav_file(file_path, min_size_bytes=1024, conf=None):
    """Enhanced WAV file validation with more thorough checks
    
    Args:
        file_path (str): Path to WAV file
        min_size_bytes (int): Minimum acceptable file size
        conf (dict, optional): Configuration settings
        
    Returns:
        bool: True if file is valid, False otherwise
    """
    # Default configuration
    if conf is None:
        conf = {}
    
    corrupt_file_dir = conf.get('CORRUPT_FILE_DIR', '')
    max_header_size = conf.get('MAX_WAV_HEADER_SIZE', 256)
    min_header_size = conf.get('WAV_MINIMUM_HEADER_SIZE', 44)
    
    try:
        # Basic file system checks
        if not os.path.exists(file_path):
            log.warning(f"File does not exist: {file_path}")
            return False
            
        # Check file size - reject empty or suspiciously small files
        file_size = os.path.getsize(file_path)
        if file_size < min_size_bytes:
            log.warning(f"File too small to be a valid WAV: {file_path} ({file_size} bytes)")
            
            # Track corrupt files
            with global_stats_lock:
                global_stats['corrupt_files_detected'] = global_stats.get('corrupt_files_detected', 0) + 1
            
            # Update metrics if available
            if HAS_PROMETHEUS:
                CORRUPT_FILES.inc()
            
            # Move or delete corrupt file
            handle_corrupt_file(file_path, corrupt_file_dir)
            return False
            
        # Check file age if configured
        max_age_days = conf.get('MAX_FILE_AGE_DAYS', 30)
        if max_age_days > 0:
            file_age_days = (time.time() - os.path.getmtime(file_path)) / (24 * 3600)
            if file_age_days > max_age_days:
                log.info(f"Skipping file older than {max_age_days} days: {file_path} ({file_age_days:.1f} days old)")
                return False
        
        # Enhanced WAV file header check - if feature flag is enabled
        if FEATURE_FLAGS["enhanced_file_validation"]:
            with open(file_path, 'rb') as f:
                header = f.read(max_header_size)  # Read more than just the basic header
                
                # Basic RIFF/WAVE check
                if len(header) < min_header_size or header[0:4] != b'RIFF' or header[8:12] != b'WAVE':
                    log.warning(f"Invalid WAV header in file: {file_path}")
                    with global_stats_lock:
                        global_stats['corrupt_files_detected'] = global_stats.get('corrupt_files_detected', 0) + 1
                    if HAS_PROMETHEUS:
                        CORRUPT_FILES.inc()
                    handle_corrupt_file(file_path, corrupt_file_dir)
                    return False
                
                # Additional sanity checks on format chunk
                try:
                    # Find 'fmt ' chunk
                    fmt_pos = header.find(b'fmt ')
                    if fmt_pos < 0:
                        log.warning(f"No format chunk in WAV header: {file_path}")
                        with global_stats_lock:
                            global_stats['corrupt_files_detected'] = global_stats.get('corrupt_files_detected', 0) + 1
                        if HAS_PROMETHEUS:
                            CORRUPT_FILES.inc()
                        handle_corrupt_file(file_path, corrupt_file_dir)
                        return False
                    
                    # Check for data chunk
                    if b'data' not in header:
                        log.warning(f"No data chunk in WAV header: {file_path}")
                        with global_stats_lock:
                            global_stats['corrupt_files_detected'] = global_stats.get('corrupt_files_detected', 0) + 1
                        if HAS_PROMETHEUS:
                            CORRUPT_FILES.inc()
                        handle_corrupt_file(file_path, corrupt_file_dir)
                        return False
                    
                    # Check file size consistency with header
                    if len(header) >= 44:  # Minimum size for basic checks
                        # RIFF chunk size (should be file size - 8)
                        riff_size = int.from_bytes(header[4:8], byteorder='little')
                        if file_size < riff_size + 8:
                            log.warning(f"File size inconsistent with RIFF header: {file_path}")
                            with global_stats_lock:
                                global_stats['corrupt_files_detected'] = global_stats.get('corrupt_files_detected', 0) + 1
                            if HAS_PROMETHEUS:
                                CORRUPT_FILES.inc()
                            handle_corrupt_file(file_path, corrupt_file_dir)
                            return False
                        
                except Exception as e:
                    log.warning(f"Error in detailed WAV validation for {file_path}: {e}")
                    # Don't reject the file based on advanced check failures
        else:
            # Basic WAV header check for backward compatibility
            with open(file_path, 'rb') as f:
                header = f.read(44)  # Standard WAV header size
                
                # Check RIFF header
                if len(header) < 12 or header[0:4] != b'RIFF' or header[8:12] != b'WAVE':
                    log.warning(f"Invalid WAV header in file: {file_path}")
                    with global_stats_lock:
                        global_stats['corrupt_files_detected'] = global_stats.get('corrupt_files_detected', 0) + 1
                    if HAS_PROMETHEUS:
                        CORRUPT_FILES.inc()
                    handle_corrupt_file(file_path, corrupt_file_dir)
                    return False
        
        # Update file size metrics
        if HAS_PROMETHEUS:
            FILE_SIZE.observe(file_size)
            
        # Track file size distribution
        with global_stats_lock:
            if file_size < 1024 * 1024:  # < 1MB
                global_stats['file_size_distribution']['0-1MB'] += 1
            elif file_size < 10 * 1024 * 1024:  # 1-10MB
                global_stats['file_size_distribution']['1-10MB'] += 1
            elif file_size < 50 * 1024 * 1024:  # 10-50MB
                global_stats['file_size_distribution']['10-50MB'] += 1
            elif file_size < 100 * 1024 * 1024:  # 50-100MB
                global_stats['file_size_distribution']['50-100MB'] += 1
            else:  # > 100MB
                global_stats['file_size_distribution']['100MB+'] += 1
        
        # Calculate and store file hash for deduplication (if memory optimized mode is enabled)
        if FEATURE_FLAGS["memory_optimized_processing"]:
            try:
                # Only hash the first 8KB of the file for speed
                with open(file_path, 'rb') as f:
                    file_hash = hashlib.md5(f.read(8192)).hexdigest()
                return True, file_hash
            except Exception as e:
                log.warning(f"Error calculating file hash for {file_path}: {e}")
        
        return True
        
    except Exception as e:
        error_id = log_error_with_context(e, 
                                        {"file": file_path, "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else None},
                                        ErrorCode.CORRUPT_FILE_ERROR)
        log.warning(f"Error validating WAV file {file_path} (ID: {error_id}): {e}")
        return False


def handle_corrupt_file(file_path, corrupt_file_dir):
    """Handle corrupt file by moving or deleting it
    
    Args:
        file_path (str): Path to corrupt file
        corrupt_file_dir (str): Directory to move corrupt files to (empty = delete)
    """
    try:
        if corrupt_file_dir and os.path.isdir(corrupt_file_dir):
            # Move to corrupt file directory
            filename = os.path.basename(file_path)
            corrupt_path = os.path.join(corrupt_file_dir, f"corrupt_{int(time.time())}_{filename}")
            shutil.move(file_path, corrupt_path)
            log.info(f"Moved corrupt file to: {corrupt_path}")
        else:
            # Delete corrupt file
            os.remove(file_path)
            log.info(f"Deleted corrupt file: {file_path}")
    except Exception as e:
        log.warning(f"Failed to handle corrupt file {file_path}: {e}")


def check_dependencies(conf=None):
    """Check and validate external dependencies and services
    
    Args:
        conf (dict, optional): Configuration settings
        
    Returns:
        dict: Dictionary of dependency statuses
    """
    if conf is None:
        conf = get_settings()
        
    # Get lists of critical and non-critical dependencies
    critical_deps = conf.get('CRITICAL_DEPENDENCIES', ['model', 'filesystem'])
    noncritical_deps = conf.get('NONCRITICAL_DEPENDENCIES', ['database', 'external_apis'])
    
    # Initialize dependency status
    dependency_status = {
        'model': {'status': 'unknown', 'last_check': time.time(), 'critical': 'model' in critical_deps},
        'database': {'status': 'unknown', 'last_check': time.time(), 'critical': 'database' in critical_deps},
        'filesystem': {'status': 'unknown', 'last_check': time.time(), 'critical': 'filesystem' in critical_deps},
        'external_apis': {'status': 'unknown', 'last_check': time.time(), 'critical': 'external_apis' in critical_deps},
        'psutil': {'status': 'available' if HAS_PSUTIL else 'unavailable', 'critical': False},
        'prometheus': {'status': 'available' if HAS_PROMETHEUS else 'unavailable', 'critical': False},
        'all_operational': True,
        'critical_failure': False
    }
    
    # Check if model is loaded
    try:
        # This is just a proxy check - your actual check might differ
        # We're just verifying that the module is imported
        import server
        model_loaded = hasattr(server, 'run_analysis') and callable(server.run_analysis)
        dependency_status['model']['status'] = 'operational' if model_loaded else 'error'
        dependency_status['model']['message'] = 'Model functions available' if model_loaded else 'Model functions not found'
        
        # Update metrics if available
        if HAS_PROMETHEUS:
            DEPENDENCY_STATUS.labels(dependency='model').set(1 if model_loaded else 0)
    except Exception as e:
        dependency_status['model']['status'] = 'error'
        dependency_status['model']['message'] = str(e)
        log.error(f"Model loading check failed: {e}")
        if HAS_PROMETHEUS:
            DEPENDENCY_STATUS.labels(dependency='model').set(0)
    
    # Check database connection
    try:
        global db_connection_pool
        if db_connection_pool is None:
            db_connection_pool = DBConnectionPool(
                max_connections=conf.get('DB_MAX_CONNECTIONS', 10),
                connection_timeout=conf.get('DB_CONNECTION_TIMEOUT', 30),
                validation_interval=conf.get('DB_VALIDATION_INTERVAL', 300)
            )
            
        # Test connection
        conn = db_connection_pool.get_connection()
        db_connection_pool.release_connection(conn)
        dependency_status['database']['status'] = 'operational'
        dependency_status['database']['message'] = 'Database connection successful'
        dependency_status['database']['pool_stats'] = db_connection_pool.get_stats()
        
        # Update metrics if available
        if HAS_PROMETHEUS:
            DEPENDENCY_STATUS.labels(dependency='database').set(1)
    except Exception as e:
        dependency_status['database']['status'] = 'error'
        dependency_status['database']['message'] = str(e)
        log.error(f"Database connection check failed: {e}")
        if HAS_PROMETHEUS:
            DEPENDENCY_STATUS.labels(dependency='database').set(0)
    
    # Check filesystem access
    try:
        # Test important directories
        test_dirs = [
            conf['RECS_DIR'],
            conf.get('STREAM_DATA_DIR', os.path.join(conf['RECS_DIR'], 'StreamData')),
            conf.get('RECOVERY_DIR', '/tmp/birdnet_recovery')
        ]
        
        fs_status = True
        issues = []
        
        for directory in test_dirs:
            if not os.path.exists(directory):
                try:
                    os.makedirs(directory, exist_ok=True)
                    issues.append(f"Created missing directory: {directory}")
                except Exception as e:
                    fs_status = False
                    issues.append(f"Failed to create directory {directory}: {e}")
                    continue
                    
            # Test write access
            test_file = os.path.join(directory, f".write_test_{uuid.uuid4().hex}")
            try:
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
            except Exception as e:
                fs_status = False
                issues.append(f"No write permission for {directory}: {e}")
        
        dependency_status['filesystem']['status'] = 'operational' if fs_status else 'error'
        dependency_status['filesystem']['message'] = 'All filesystem checks passed' if fs_status else '; '.join(issues)
        
        # Update metrics if available
        if HAS_PROMETHEUS:
            DEPENDENCY_STATUS.labels(dependency='filesystem').set(1 if fs_status else 0)
    except Exception as e:
        dependency_status['filesystem']['status'] = 'error'
        dependency_status['filesystem']['message'] = str(e)
        log.error(f"Filesystem check failed: {e}")
        if HAS_PROMETHEUS:
            DEPENDENCY_STATUS.labels(dependency='filesystem').set(0)
    
    # Check external API integrations (Apprise, Weather, etc.)
    try:
        # This is a placeholder for actual API checks
        external_apis_ok = True
        api_issues = []
        
        # Check apprise if it's configured
        if hasattr(apprise, '_get_notifiers') and callable(apprise._get_notifiers):
            notifiers = apprise._get_notifiers()
            if not notifiers:
                external_apis_ok = False
                api_issues.append("Apprise notifiers not configured")
        else:
            api_issues.append("Apprise not properly configured")
        
        # Check weather API if it's configured
        if hasattr(bird_weather, 'is_configured') and callable(bird_weather.is_configured):
            weather_ok = bird_weather.is_configured()
            if not weather_ok:
                api_issues.append("Weather API not configured")
        else:
            api_issues.append("Weather API check not available")
        
        dependency_status['external_apis']['status'] = 'operational' if external_apis_ok else 'degraded'
        dependency_status['external_apis']['message'] = (
            'External APIs operational' if external_apis_ok else '; '.join(api_issues)
        )
        
        # Update metrics if available
        if HAS_PROMETHEUS:
            DEPENDENCY_STATUS.labels(dependency='external_apis').set(1 if external_apis_ok else 0.5)  # 0.5 for degraded
    except Exception as e:
        dependency_status['external_apis']['status'] = 'error'
        dependency_status['external_apis']['message'] = str(e)
        log.warning(f"External API check failed: {e}")
        if HAS_PROMETHEUS:
            DEPENDENCY_STATUS.labels(dependency='external_apis').set(0)
    
    # Check for critical failures
    for dep_name, dep_info in dependency_status.items():
        if isinstance(dep_info, dict) and dep_info.get('status') == 'error' and dep_info.get('critical', False):
            dependency_status['critical_failure'] = True
            log.error(f"Critical dependency failure: {dep_name} - {dep_info.get('message', 'Unknown error')}")
            break
    
    # Check if all dependencies are operational
    all_operational = True
    for dep_name, dep_info in dependency_status.items():
        if isinstance(dep_info, dict) and dep_info.get('status') not in ['operational', 'available']:
            all_operational = False
            break
    dependency_status['all_operational'] = all_operational
    
    # Update global stats with thread safety
    with global_stats_lock:
        global_stats['dependencies'] = {
            k: v for k, v in dependency_status.items() 
            if k not in ['all_operational', 'critical_failure', 'psutil', 'prometheus']
        }
    
    return dependency_status


def manage_processed_files(processed_files, file_path, file_hash=None, max_size=10000):
    """Manage the processed files data structure to prevent memory growth
    
    Args:
        processed_files (OrderedDict): OrderedDict of processed files
        file_path (str): Path to file to add
        file_hash (str, optional): Hash of file content for deduplication
        max_size (int): Maximum number of files to track
        
    Returns:
        OrderedDict: Updated processed_files
    """
    with processed_files_lock:
        # If we're using file hashing for deduplication
        if file_hash and FEATURE_FLAGS["memory_optimized_processing"]:
            # Check if we've seen this hash before
            for path, data in processed_files.items():
                if isinstance(data, dict) and data.get('hash') == file_hash:
                    log.debug(f"Skipping duplicate file content: {file_path} matches {path}")
                    # Still add this path but mark it as a duplicate
                    processed_files[file_path] = {
                        'time': time.time(),
                        'hash': file_hash,
                        'duplicate': True,
                        'original': path
                    }
                    return processed_files
            
            # New file hash
            processed_files[file_path] = {
                'time': time.time(),
                'hash': file_hash,
                'duplicate': False
            }
        else:
            # Just track by path
            processed_files[file_path] = time.time()
        
        # Trim if needed - OrderedDict preserves insertion order
        if len(processed_files) > max_size:
            # Remove oldest 20% of entries to avoid frequent trimming
            remove_count = max_size // 5
            for _ in range(remove_count):
                try:
                    processed_files.popitem(last=False)  # Remove oldest item (FIFO)
                except KeyError:
                    break  # Safety check
            
            log.info(f"Trimmed processed_files to {len(processed_files)} entries")
            
        return processed_files


def main():
    """Main processing function for BirdNet analysis"""
    with global_stats_lock:
        global_stats['start_time'] = time.time()
    
    log.info(f"Starting BirdNet Analysis v{SCRIPT_VERSION}")
    
    try:
        # Validate configuration first
        conf = validate_configuration(get_settings())
        log.info(f"Configuration validated successfully")
        
        # Apply thread priority if configured
        thread_priority = conf.get('WORKER_THREAD_PRIORITY', 0)
        if thread_priority != 0 and hasattr(os, 'nice'):
            try:
                os.nice(thread_priority)
                log.info(f"Set thread priority adjustment to {thread_priority}")
            except Exception as e:
                log.warning(f"Could not set thread priority: {e}")
        
        # Start metrics server if enabled
        if conf.get('ENABLE_METRICS', False) and HAS_PROMETHEUS:
            metrics_port = conf.get('METRICS_PORT', 9090)
            try:
                start_http_server(metrics_port)
                log.info(f"Prometheus metrics server started on port {metrics_port}")
            except Exception as e:
                log.warning(f"Failed to start metrics server: {e}")
        
        # Check for legacy mode
        legacy_mode = conf.get('LEGACY_MODE', False)
        if legacy_mode:
            log.info("Running in legacy compatibility mode")
        
        # Initialize recovery and health monitoring
        recovery_file = conf['RECOVERY_FILE']
        health_check_file = conf['HEALTH_CHECK_FILE']
        health_interval = conf['HEALTH_INTERVAL']
        state_save_interval = conf['STATE_SAVE_INTERVAL']
        
        # Initialize database connection pool
        global db_connection_pool
        db_connection_pool = DBConnectionPool(
            max_connections=conf.get('DB_MAX_CONNECTIONS', 10),
            connection_timeout=conf.get('DB_CONNECTION_TIMEOUT', 30),
            validation_interval=conf.get('DB_VALIDATION_INTERVAL', 300)
        )
        
        # Check dependencies and fast-fail if critical ones are missing
        log.info("Checking dependencies and loading global model...")
        dependency_status = check_dependencies(conf)
        
        # Update health status with initial dependency check
        update_health_file(health_check_file, "starting", {
            "dependencies": dependency_status
        })
        
        # Fail fast if critical dependencies are not available
        if dependency_status['critical_failure'] and conf.get('FAST_FAILURE_MODE', False):
            critical_errors = [
                f"{dep}: {info['message']}" 
                for dep, info in dependency_status.items() 
                if isinstance(info, dict) and info.get('critical', False) and info['status'] == 'error'
            ]
            raise RuntimeError(f"Critical dependencies unavailable: {', '.join(critical_errors)}")
        
        # Load global model with retry for robustness
        load_global_model_with_retry = retry(
            max_attempts=3,
            delay=2.0,
            backoff=2.0,
            jitter=FEATURE_FLAGS["jitter_backoff"],
            exceptions=(Exception,)
        )(load_global_model)
        
        try:
            load_global_model_with_retry()
        except Exception as e:
            error_id = log_error_with_context(e, {"context": "model_loading"}, ErrorCode.MODEL_ERROR)
            raise RuntimeError(f"Failed to load global model after retries (ID: {error_id}): {e}")
        
        # Resource management settings
        max_queue_size = conf['MAX_QUEUE_SIZE']
        max_workers = conf['MAX_WORKERS']
        backlog_chunk_size = conf['BACKLOG_CHUNK_SIZE']
        
        # Path validation strictness
        path_validation_strict = conf.get('PATH_VALIDATION_STRICT', True)
        
        # Make StreamData path configurable with backward compatibility
        stream_data_path = conf.get('STREAM_DATA_DIR', os.path.join(conf['RECS_DIR'], 'StreamData'))
        base_dir = os.path.abspath(conf['RECS_DIR'])
        
        log.info(f"Monitoring directory: {stream_data_path}")
        
        # Initialize inotify
        i = inotify.adapters.Inotify()
        try:
            i.add_watch(stream_data_path, mask=IN_CLOSE_WRITE)
        except Exception as e:
            error_id = log_error_with_context(e, {"context": "inotify_setup", "path": stream_data_path}, ErrorCode.CONFIGURATION_ERROR)
            raise RuntimeError(f"Failed to set up inotify watch (ID: {error_id}): {e}")

        # Set up processing state with recovery
        processed_files_from_recovery, queue_items_from_recovery = load_processing_state(recovery_file)
        
        log.info("Getting backlog of WAV files...")
        backlog = get_wav_files()
        
        # Initialize processed_files as an OrderedDict to maintain insertion order
        processed_files = collections.OrderedDict()
        with processed_files_lock:
            # Add files from backlog
            for file in backlog:
                sanitized = sanitize_path(file, base_dir, strict=path_validation_strict)
                if sanitized:
                    processed_files[sanitized] = time.time()
            
            # Add recovered files
            for file in processed_files_from_recovery:
                sanitized = sanitize_path(file, base_dir, strict=path_validation_strict)
                if sanitized:
                    # If it's a dict with details, preserve them
                    if isinstance(processed_files_from_recovery, dict) and isinstance(processed_files_from_recovery.get(file), dict):
                        processed_files[sanitized] = processed_files_from_recovery[file]
                    else:
                        processed_files[sanitized] = time.time()
        
        # Update global stats with thread safety
        with global_stats_lock:
            global_stats['backlog_size'] = len(backlog)
            
        # Update metrics if enabled
        if HAS_PROMETHEUS:
            BACKLOG_SIZE.set(len(backlog))
            with processed_files_lock:
                PROCESSED_FILES_SET_SIZE.set(len(processed_files))

        # Initialize reporting queue with size limit
        report_queue = Queue(maxsize=max_queue_size)
        
        # Start reporting thread
        thread = threading.Thread(
            target=handle_reporting_queue, 
            args=(report_queue, conf),
            name="ReportingThread"
        )
        thread.daemon = True
        thread.start()
        
        # Restore queue items from recovery if available
        for item in queue_items_from_recovery:
            try:
                file_name, detections = item
                sanitized = sanitize_path(file_name, base_dir, strict=path_validation_strict)
                if sanitized:
                    report_queue.put((file_name, detections))
                    log.info(f"Restored queue item from recovery: {os.path.basename(file_name)}")
            except Exception as e:
                log.warning(f"Could not restore queue item from recovery: {e}")

        # Process backlog
        backlog_count = len(backlog)
        log.info(f'Backlog is {backlog_count} files')
        
        update_health_file(health_check_file, "running", {
            "queue_size": report_queue.qsize(),
            "backlog_size": backlog_count,
            "processed_files": len(processed_files)
        })
        
        # Process backlog
        if backlog and not shutdown:
            if legacy_mode:
                # Process backlog sequentially for compatibility
                log.info("Processing backlog sequentially (legacy mode)")
                for file_name in backlog:
                    if shutdown:
                        break
                    sanitized = sanitize_path(file_name, base_dir, strict=path_validation_strict)
                    if sanitized:
                        try:
                            # Validate file before processing
                            is_valid = validate_wav_file(sanitized, conf=conf)
                            if isinstance(is_valid, tuple):
                                is_valid, file_hash = is_valid
                            else:
                                file_hash = None
                                
                            if is_valid:
                                # Update processed files tracking
                                processed_files = manage_processed_files(
                                    processed_files, sanitized, file_hash, 
                                    conf.get('PROCESSED_FILES_MEMORY_LIMIT', 10000)
                                )
                                
                                # Process the file
                                process_file(sanitized, report_queue, conf, base_dir)
                                with global_stats_lock:
                                    global_stats['processed_count'] += 1
                                    
                                # Update metrics if enabled
                                if HAS_PROMETHEUS:
                                    PROCESSED_FILES.inc()
                            else:
                                with global_stats_lock:
                                    global_stats['skipped_count'] += 1
                                    
                                # Update metrics if enabled
                                if HAS_PROMETHEUS:
                                    SKIPPED_FILES.inc()
                        except Exception as e:
                            with global_stats_lock:
                                global_stats['error_count'] += 1
                            error_id = log_error_with_context(e, {"context": "legacy_backlog", "file": file_name}, ErrorCode.GENERAL_ERROR)
                            log.error(f"Error in legacy backlog processing (ID: {error_id}): {e}")
                    if shutdown:
                        break
            else:
                # Process backlog with worker pool in chunks
                log.info(f"Processing backlog with {max_workers} workers")
                
                # Use smaller chunks to process for better progress reporting
                chunk_size = min(backlog_chunk_size, max(10, backlog_count // 10))
                chunks = [backlog[i:i+chunk_size] for i in range(0, backlog_count, chunk_size)]
                
                for chunk_idx, chunk in enumerate(chunks):
                    if shutdown:
                        break
                        
                    log.info(f"Processing backlog chunk {chunk_idx+1}/{len(chunks)} ({len(chunk)} files)")
                    with ThreadPoolExecutor(max_workers=max_workers) as executor:
                        # Process backlog in parallel
                        futures = []
                        for file_name in chunk:
                            sanitized = sanitize_path(file_name, base_dir, strict=path_validation_strict)
                            if sanitized:
                                # Validate file before submitting to thread pool
                                is_valid = validate_wav_file(sanitized, conf=conf)
                                if isinstance(is_valid, tuple):
                                    is_valid, file_hash = is_valid
                                else:
                                    file_hash = None
                                    
                                if is_valid:
                                    # Update processed files tracking
                                    processed_files = manage_processed_files(
                                        processed_files, sanitized, file_hash, 
                                        conf.get('PROCESSED_FILES_MEMORY_LIMIT', 10000)
                                    )
                                    
                                    # Check if this is a duplicate file we can skip
                                    is_duplicate = False
                                    if FEATURE_FLAGS["memory_optimized_processing"] and file_hash:
                                        file_data = processed_files.get(sanitized)
                                        if isinstance(file_data, dict) and file_data.get('duplicate', False):
                                            is_duplicate = True
                                            log.debug(f"Skipping duplicate file: {sanitized} (duplicate of {file_data.get('original')})")
                                            with global_stats_lock:
                                                global_stats['skipped_count'] += 1
                                            if HAS_PROMETHEUS:
                                                SKIPPED_FILES.inc()
                                    
                                    if not is_duplicate:
                                        futures.append(
                                            executor.submit(process_file, sanitized, report_queue, conf, base_dir)
                                        )
                                else:
                                    with global_stats_lock:
                                        global_stats['skipped_count'] += 1
                                    if HAS_PROMETHEUS:
                                        SKIPPED_FILES.inc()
                        
                        for idx, future in enumerate(futures):
                            try:
                                future.result()
                                with global_stats_lock:
                                    global_stats['processed_count'] += 1
                                if HAS_PROMETHEUS:
                                    PROCESSED_FILES.inc()
                            except Exception as e:
                                with global_stats_lock:
                                    global_stats['error_count'] += 1
                                error_id = log_error_with_context(e, {"context": "backlog_processing"}, ErrorCode.GENERAL_ERROR)
                                log.error(f"Error in backlog processing (ID: {error_id}): {e}")
                                
                            # Update progress periodically
                            if idx % 10 == 0 or idx == len(futures) - 1:
                                progress = (chunk_idx * chunk_size + idx + 1) / backlog_count * 100
                                log.info(f"Backlog progress: {progress:.1f}% ({chunk_idx * chunk_size + idx + 1}/{backlog_count})")
                                
                                # Update health check
                                update_health_file(health_check_file, "running", {
                                    "queue_size": report_queue.qsize(),
                                    "backlog_progress": f"{progress:.1f}%",
                                    "processed_files": global_stats['processed_count'],
                                    "error_count": global_stats['error_count']
                                })
                                
                                # Update metrics if enabled
                                if HAS_PROMETHEUS:
                                    QUEUE_SIZE.set(report_queue.qsize())
                    
                    # Save state after each chunk
                    save_processing_state(processed_files, [], recovery_file)
        
        log.info('Backlog processing completed')

        # Update health immediately after backlog
        update_health_file(health_check_file, "monitoring", {
            "queue_size": report_queue.qsize(),
            "processed_files": global_stats['processed_count'],
            "error_count": global_stats['error_count']
        })

        # Main event loop
        empty_count = 0
        throttle_delay = conf['THROTTLE_DELAY']
        dependency_check_interval = conf.get('DEPENDENCY_CHECK_INTERVAL', 600)
        last_dependency_check = time.time()
        
        log.info("Starting main monitoring loop")
        for event in i.event_gen():
            if shutdown:
                log.info("Shutdown signal received, exiting monitoring loop")
                break
            
            # Periodically check dependencies
            current_time = time.time()
            if current_time - last_dependency_check > dependency_check_interval:
                last_dependency_check = current_time
                try:
                    log.debug("Performing periodic dependency check")
                    dependency_status = check_dependencies(conf)
                    
                    # Log if there are issues but not critical failures
                    if not dependency_status['all_operational'] and not dependency_status['critical_failure']:
                        log.warning("One or more non-critical dependencies have issues")
                        for dep_name, dep_info in dependency_status.items():
                            if isinstance(dep_info, dict) and dep_info.get('status') not in ['operational', 'available', 'unknown']:
                                log.warning(f"Dependency issue: {dep_name} - {dep_info.get('message', 'Unknown error')}")
                    
                    # Critical failures in fast-failure mode should trigger shutdown
                    if dependency_status['critical_failure'] and conf.get('FAST_FAILURE_MODE', False):
                        log.error("Critical dependency failure detected in fast-failure mode. Initiating shutdown.")
                        shutdown = True
                        shutdown_event.set()
                        break
                except Exception as e:
                    log.warning(f"Error during periodic dependency check: {e}")
            
            # Periodically update health
            if 'last_health_update' not in global_stats or current_time - global_stats['last_health_update'] > health_interval:
                with global_stats_lock:
                    global_stats['last_health_update'] = current_time
                    
                # Update metrics if enabled
                if HAS_PROMETHEUS:
                    with processed_files_lock:
                        PROCESSED_FILES_SET_SIZE.set(len(processed_files))
                    QUEUE_SIZE.set(report_queue.qsize())
                
                update_health_file(health_check_file, "monitoring", {
                    "queue_size": report_queue.qsize(),
                    "processed_files": global_stats['processed_count'],
                    "error_count": global_stats['error_count'],
                    "skipped_count": global_stats['skipped_count'],
                    "uptime_seconds": int(current_time - global_stats['start_time']),
                    "recent_file_count": len(processed_files)
                })
            
            # Periodically save state
            if 'last_state_save' not in global_stats or current_time - global_stats['last_state_save'] > state_save_interval:
                with global_stats_lock:
                    global_stats['last_state_save'] = current_time
                save_processing_state(processed_files, [], recovery_file)

            if event is None:
                max_empty_count = (conf['RECORDING_LENGTH'] * 2 + 30)
                if empty_count > max_empty_count:
                    log.error('No more notifications: restarting...')
                    break
                empty_count += 1
                time.sleep(throttle_delay)  # Avoid busy waiting
                continue

            # Handle file event
            (_, type_names, path, file_name) = event
            if re.search('.wav$', file_name) is None:
                continue
            
            log.debug("PATH=[%s] FILENAME=[%s] EVENT_TYPES=%s", path, file_name, type_names)

            file_path = os.path.join(path, file_name)
            file_path = sanitize_path(file_path, base_dir, strict=path_validation_strict)
            
            if not file_path:
                log.warning(f"Skipping file with invalid path: {os.path.join(path, file_name)}")
                with global_stats_lock:
                    global_stats['skipped_count'] += 1
                if HAS_PROMETHEUS:
                    SKIPPED_FILES.inc()
                continue
            
            # Prevent double processing of files (with thread safety)
            with processed_files_lock:
                if file_path in processed_files:
                    log.debug(f'Skipping already processed file: {file_path}')
                    with global_stats_lock:
                        global_stats['skipped_count'] += 1
                    if HAS_PROMETHEUS:
                        SKIPPED_FILES.inc()
                    continue
            
            # Check for system overload and throttle if needed
            is_overloaded, metrics = is_system_overloaded(conf)
            if is_overloaded:
                overload_delay = conf['OVERLOAD_DELAY']
                log.info(f"System load high, throttling for {overload_delay} seconds: {metrics.get('reason', 'Unknown reason')}")
                time.sleep(overload_delay)
            
            # Validate file before processing
            is_valid = validate_wav_file(file_path, conf=conf)
            file_hash = None
            
            if isinstance(is_valid, tuple):
                is_valid, file_hash = is_valid
                
            if not is_valid:
                with global_stats_lock:
                    global_stats['skipped_count'] += 1
                if HAS_PROMETHEUS:
                    SKIPPED_FILES.inc()
                continue
            
            # Update the processed files tracking with new validated file
            processed_files = manage_processed_files(
                processed_files, file_path, file_hash, 
                conf.get('PROCESSED_FILES_MEMORY_LIMIT', 10000)
            )
            
            # Check if this is a duplicate file we can skip (optimization)
            if FEATURE_FLAGS["memory_optimized_processing"] and file_hash:
                with processed_files_lock:
                    file_data = processed_files.get(file_path)
                    if isinstance(file_data, dict) and file_data.get('duplicate', False):
                        log.debug(f"Skipping duplicate file: {file_path} (duplicate of {file_data.get('original')})")
                        with global_stats_lock:
                            global_stats['skipped_count'] += 1
                        if HAS_PROMETHEUS:
                            SKIPPED_FILES.inc()
                        continue
            
            # Process the file
            try:
                process_file(file_path, report_queue, conf, base_dir)
                with global_stats_lock:
                    global_stats['processed_count'] += 1
                if HAS_PROMETHEUS:
                    PROCESSED_FILES.inc()
            except Exception as e:
                with global_stats_lock:
                    global_stats['error_count'] += 1
                error_id = log_error_with_context(e, {"context": "main_loop_processing", "file": file_path}, ErrorCode.GENERAL_ERROR)
                log.error(f"Error processing file (ID: {error_id}): {e}")
                
            empty_count = 0
