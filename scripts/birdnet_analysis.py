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

# Global variables
shutdown = False
shutdown_event = Event()  # Thread-safe event for signaling shutdown
force_timer = None  # Timer for forced shutdown
log = logging.getLogger(__name__)
SCRIPT_VERSION = "1.3.0"  # Updated version with production enhancements

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
    }
}

# Connection pool for database operations
db_connection_pool = None

# Prometheus metrics (if available)
if HAS_PROMETHEUS:
    # Counters
    PROCESSED_FILES = Counter('birdnet_processed_files_total', 'Total number of files processed')
    ERROR_COUNT = Counter('birdnet_errors_total', 'Total number of errors encountered')
    SKIPPED_FILES = Counter('birdnet_skipped_files_total', 'Total number of files skipped')
    CORRUPT_FILES = Counter('birdnet_corrupt_files_total', 'Total number of corrupt files detected')
    TIMEOUT_COUNT = Counter('birdnet_timeouts_total', 'Total number of analysis timeouts')
    
    # Gauges
    QUEUE_SIZE = Gauge('birdnet_queue_size', 'Current size of the reporting queue')
    BACKLOG_SIZE = Gauge('birdnet_backlog_size', 'Current size of the file backlog')
    PROCESSED_FILES_SET_SIZE = Gauge('birdnet_processed_files_set_size', 'Size of the processed files tracking set')
    MEMORY_USAGE = Gauge('birdnet_memory_usage_percent', 'Current memory usage percentage')
    CPU_USAGE = Gauge('birdnet_cpu_usage_percent', 'Current CPU usage percentage')
    
    # Histograms
    FILE_SIZE = Histogram('birdnet_file_size_bytes', 'Size of processed files in bytes', buckets=(1024*1024, 10*1024*1024, 50*1024*1024, 100*1024*1024, float('inf')))
    ANALYSIS_DURATION = Histogram('birdnet_analysis_duration_seconds', 'Duration of analysis operations', buckets=(0.5, 1, 2, 5, 10, 30, 60, 120))


class CircuitBreaker:
    """Circuit breaker pattern implementation for external service calls
    
    Prevents cascading failures by temporarily disabling calls to failing services.
    
    Args:
        name (str): Identifier for the circuit breaker
        failure_threshold (int): Number of failures before opening circuit
        reset_timeout (int): Seconds to wait before attempting reset
    """
    def __init__(self, name, failure_threshold=5, reset_timeout=60):
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.failures = 0
        self.last_failure = 0
        self.open = False
        self.total_failures = 0
        self.total_successes = 0
        self.lock = Lock()  # Add thread safety
    
    def can_execute(self):
        """Check if the protected operation can be executed
        
        Returns:
            bool: True if circuit is closed or can be reset, False otherwise
        """
        with self.lock:
            if not self.open:
                return True
            
            # Check if circuit should be reset
            if time.time() - self.last_failure > self.reset_timeout:
                log.info(f"Circuit breaker for {self.name} reset after timeout")
                self.open = False
                self.failures = 0
                return True
            return False
    
    def record_failure(self):
        """Record a failure and potentially open the circuit"""
        with self.lock:
            self.failures += 1
            self.total_failures += 1
            self.last_failure = time.time()
            if self.failures >= self.failure_threshold and not self.open:
                log.warning(f"Circuit breaker for {self.name} opened after {self.failures} failures")
                self.open = True
                
    def record_success(self):
        """Record a success and potentially close the circuit"""
        with self.lock:
            self.total_successes += 1
            if self.open:
                self.open = False
                self.failures = 0
                log.info(f"Circuit breaker for {self.name} closed after success")
            elif self.failures > 0:
                self.failures = 0
                
    def get_stats(self):
        """Get statistics about the circuit breaker
        
        Returns:
            dict: Statistics about successes and failures
        """
        with self.lock:
            return {
                "name": self.name,
                "open": self.open,
                "failures": self.failures,
                "total_failures": self.total_failures,
                "total_successes": self.total_successes,
                "success_rate": self._calculate_success_rate()
            }
    
    def _calculate_success_rate(self):
        """Calculate success rate
        
        Returns:
            float: Success rate as percentage, or None if no operations
        """
        total = self.total_successes + self.total_failures
        if total == 0:
            return None
        return (self.total_successes / total) * 100


class DBConnectionPool:
    """Simple connection pool for database operations
    
    This provides a thread-safe way to manage and reuse database connections
    """
    def __init__(self, max_connections=10, connection_timeout=30):
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout
        self.pool = Queue(maxsize=max_connections)
        self.active_connections = 0
        self.lock = Lock()
        self.pool_initialized = False
        
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
                    except Exception as e:
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
            
        # Try to get a connection from the pool
        try:
            connection = self.pool.get(block=True, timeout=self.connection_timeout)
            # Validate connection before returning
            if not self._validate_connection(connection):
                connection = self._create_connection()
            return connection
        except Empty:
            # If pool is empty, create new connection if under limit
            with self.lock:
                if self.active_connections < self.max_connections:
                    self.active_connections += 1
                    return self._create_connection()
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
            try:
                new_connection = self._create_connection()
                self.pool.put(new_connection)
            except Exception as e:
                with self.lock:
                    self.active_connections -= 1
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
            connection = sqlite3.connect(db_path, timeout=30)
            
            # Test connection
            cursor = connection.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            
            return connection
        except ImportError:
            log.warning("SQLite3 not available, using dummy connection")
            # Dummy connection for testing
            class DummyConnection:
                def close(self):
                    pass
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
        except Exception as e:
            log.warning(f"Error closing database connection: {e}")


def retry(max_attempts=3, delay=1.0, backoff=2.0, exceptions=(Exception,), logger=None):
    """Retry decorator with exponential backoff
    
    Args:
        max_attempts: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        backoff: Backoff multiplier (e.g. value of 2 will double the delay each retry)
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
                        _logger.warning(
                            f"Retry {attempt}/{max_attempts} for {func.__name__} "
                            f"after error: {str(e)}. Retrying in {_delay:.1f}s"
                        )
                        time.sleep(_delay)
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
        
    norm_path = os.path.normpath(path)
    
    if os.path.isabs(norm_path) and base_dir:
        base_dir = os.path.abspath(base_dir)
        # Convert absolute path to relative if necessary
        if not norm_path.startswith(base_dir):
            log.warning(f"Attempt to access file outside base directory: {path}")
            if strict:
                return None
            # In non-strict mode, try to make the path relative to base_dir
            try:
                rel_path = os.path.basename(norm_path)
                new_path = os.path.join(base_dir, rel_path)
                log.warning(f"Converting absolute path to base directory: {new_path}")
                return new_path
            except Exception:
                return None
    
    # Check for other dangerous patterns
    if '..' in norm_path.split(os.sep) and strict:
        log.warning(f"Path contains parent directory references: {path}")
        return None
        
    return norm_path


def is_system_overloaded(conf):
    """Check if system resources are overloaded
    
    Args:
        conf (dict): Configuration settings
        
    Returns:
        bool: True if system is overloaded, False otherwise
    """
    # Thresholds
    max_memory_percent = conf.get('MAX_MEMORY_PERCENT', 85)
    cpu_warning_threshold = conf.get('CPU_WARNING_THRESHOLD', 80)
    disk_warning_threshold = conf.get('DISK_WARNING_THRESHOLD', 90)
    
    # Check load
    try:
        if HAS_PSUTIL:
            # Use psutil if available for better resource monitoring
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory_percent = psutil.virtual_memory().percent
            disk_percent = psutil.disk_usage('/').percent
            
            # Update metrics if enabled
            if HAS_PROMETHEUS:
                MEMORY_USAGE.set(memory_percent)
                CPU_USAGE.set(cpu_percent)
            
            # Add memory info to global stats with thread safety
            with global_stats_lock:
                if 'memory_usage' not in global_stats:
                    global_stats['memory_usage'] = []
                
                # Keep last readings based on configured retention
                memory_data = {
                    'timestamp': time.time(),
                    'memory_percent': memory_percent,
                    'cpu_percent': cpu_percent,
                    'disk_percent': disk_percent
                }
                
                global_stats['memory_usage'].append(memory_data)
                retention = conf.get('STATS_RETENTION_COUNT', 100)
                if len(global_stats['memory_usage']) > retention:
                    global_stats['memory_usage'] = global_stats['memory_usage'][-retention:]
            
            # Log warnings if resources are high but not critical
            if memory_percent > max_memory_percent * 0.9 and memory_percent <= max_memory_percent:
                log.warning(f"Memory usage approaching threshold: {memory_percent:.1f}%")
            if cpu_percent > cpu_warning_threshold * 0.9 and cpu_percent <= cpu_warning_threshold:
                log.warning(f"CPU usage approaching threshold: {cpu_percent:.1f}%")
            if disk_percent > disk_warning_threshold * 0.9 and disk_percent <= disk_warning_threshold:
                log.warning(f"Disk usage approaching threshold: {disk_percent:.1f}%")
            
            # Return True if any resource is critically high
            is_overloaded = (cpu_percent > cpu_warning_threshold or 
                            memory_percent > max_memory_percent or 
                            disk_percent > disk_warning_threshold)
            
            if is_overloaded:
                log.warning(f"System overloaded: CPU={cpu_percent:.1f}%, Memory={memory_percent:.1f}%, Disk={disk_percent:.1f}%")
                
            return is_overloaded
        else:
            # Fallback to basic load average check
            load = os.getloadavg()[0]
            cpu_count = os.cpu_count() or 1
            is_overloaded = load > (cpu_count * 0.8)  # 80% of available CPUs
            
            if is_overloaded:
                log.warning(f"System load high: {load:.1f} (threshold: {cpu_count * 0.8:.1f})")
                
            return is_overloaded
    except Exception as e:
        log.warning(f"Error checking system load: {e}")
        return False


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
    temp_filepath = f"{filepath}.{uuid.uuid4().hex}.tmp"
    
    try:
        with open(temp_filepath, 'w') as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())  # Ensure data is written to disk
            
        # Perform atomic rename
        os.replace(temp_filepath, filepath)
    except Exception as e:
        # Clean up temp file if it exists
        if os.path.exists(temp_filepath):
            try:
                os.remove(temp_filepath)
            except Exception:
                pass
        raise e


def save_processing_state(processed_files, queue_items, recovery_file):
    """Save current processing state for recovery
    
    Args:
        processed_files (set): Set of processed file paths
        queue_items (list): Current queue items for recovery
        recovery_file (str): Path to recovery file
    """
    try:
        # Create directory if needed
        os.makedirs(os.path.dirname(recovery_file), exist_ok=True)
        
        # Convert processed_files set to list and trim to reasonable size with thread safety
        with processed_files_lock:
            processed_list = list(processed_files)
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
                
            log.info(f"Loaded recovery state from {recovery_file}")
            return set(state.get('processed_files', [])), state.get('queue_items', [])
    except Exception as e:
        log.warning(f"Failed to load recovery state: {e}")
    
    return set(), []


def log_error_with_context(e, context=None):
    """Log error with additional context information
    
    Args:
        e (Exception): Exception to log
        context (dict, optional): Additional context information
        
    Returns:
        str: Error ID for reference
    """
    error_id = str(uuid.uuid4())[:8]  # Generate short ID for error tracking
    
    # Gather system information
    system_info = {
        'error_id': error_id,
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
    log.error(f"Error[{error_id}] {e.__class__.__name__}: {str(e)} | {context_str}\n{tb}")
    
    # Update error counter with thread safety
    with global_stats_lock:
        global_stats['error_count'] = global_stats.get('error_count', 0) + 1
    
    # Update metrics if available
    if HAS_PROMETHEUS:
        ERROR_COUNT.inc()
    
    # Save error details to file for later analysis
    try:
        error_log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'errors')
        os.makedirs(error_log_dir, exist_ok=True)
        
        error_file = os.path.join(error_log_dir, f"error_{error_id}_{int(time.time())}.json")
        atomic_write_json({
            'error': {
                'type': e.__class__.__name__,
                'message': str(e),
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
                    "slow_analyses": global_stats.get("slow_analyses", 0)
                }
            
            health_data = {
                "timestamp": time.time(),
                "status": status,
                "hostname": socket.gethostname(),
                "pid": os.getpid(),
                "version": SCRIPT_VERSION,
                "uptime": int(time.time() - global_stats.get('start_time', time.time()))
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
                        "disk_percent": disk_percent
                    })
                    
                    # Add warning flags
                    health_data["memory_warning"] = memory_percent > 80
                    health_data["cpu_warning"] = cpu_percent > 80
                    health_data["disk_warning"] = disk_percent > 90
                    
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
    """Validate if a WAV file is not corrupt and has proper format
    
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
        
        # Check WAV file header
        with open(file_path, 'rb') as f:
            header = f.read(44)  # Standard WAV header size
            
            # Check RIFF header
            if len(header) < 12 or header[0:4] != b'RIFF' or header[8:12] != b'WAVE':
                log.warning(f"Invalid WAV header in file: {file_path}")
                
                # Track corrupt files
                with global_stats_lock:
                    global_stats['corrupt_files_detected'] = global_stats.get('corrupt_files_detected', 0) + 1
                
                # Update metrics if available
                if HAS_PROMETHEUS:
                    CORRUPT_FILES.inc()
                
                # Move or delete corrupt file
                handle_corrupt_file(file_path, corrupt_file_dir)
                return False
                
            # Additional header validation could be added here
        
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
        
        return True
        
    except Exception as e:
        log.warning(f"Error validating WAV file {file_path}: {e}")
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


def check_dependencies():
    """Check and validate external dependencies and services
    
    Returns:
        dict: Dictionary of dependency statuses
    """
    dependency_status = {
        'model_loaded': False,
        'database': False,
        'apprise': False,
        'weather': False,
        'disk_writable': False,
        'psutil': HAS_PSUTIL,
        'prometheus': HAS_PROMETHEUS
    }
    
    # Check if model is loaded
    try:
        # This is just a proxy check - your actual check might differ
        # We're just verifying that the module is imported
        import server
        dependency_status['model_loaded'] = True
    except Exception as e:
        log.error(f"Model loading check failed: {e}")
    
    # Check database connection
    try:
        global db_connection_pool
        if db_connection_pool is None:
            conf = get_settings()
            db_connection_pool = DBConnectionPool(
                max_connections=conf.get('DB_MAX_CONNECTIONS', 10),
                connection_timeout=conf.get('DB_CONNECTION_TIMEOUT', 30)
            )
            
        # Test connection
        conn = db_connection_pool.get_connection()
        db_connection_pool.release_connection(conn)
        dependency_status['database'] = True
    except Exception as e:
        log.error(f"Database connection check failed: {e}")
    
    # Check apprise configuration
    try:
        # This is a placeholder - modify according to your actual apprise setup
        from utils.reporting import apprise
        dependency_status['apprise'] = True
    except Exception as e:
        log.warning(f"Apprise configuration check failed: {e}")
    
    # Check weather API
    try:
        # This is a placeholder - modify according to your actual weather API setup
        from utils.reporting import bird_weather
        dependency_status['weather'] = True
    except Exception as e:
        log.warning(f"Weather API check failed: {e}")
    
    # Check disk write permissions for important directories
    try:
        conf = get_settings()
        test_dirs = [
            conf['RECS_DIR'],
            conf.get('STREAM_DATA_DIR', os.path.join(conf['RECS_DIR'], 'StreamData')),
            conf.get('RECOVERY_DIR', '/tmp/birdnet_recovery')
        ]
        
        all_writable = True
        for directory in test_dirs:
            if not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
                
            test_file = os.path.join(directory, f".write_test_{uuid.uuid4().hex}")
            try:
                with open(test_file, 'w') as f:
                    f.write('test')
                os.remove(test_file)
            except Exception:
                all_writable = False
                break
                
        dependency_status['disk_writable'] = all_writable
    except Exception as e:
        log.error(f"Disk write permission check failed: {e}")
    
    return dependency_status


def main():
    """Main processing function for BirdNet analysis"""
    with global_stats_lock:
        global_stats['start_time'] = time.time()
    
    log.info(f"Starting BirdNet Analysis v{SCRIPT_VERSION}")
    
    try:
        # Validate configuration first
        conf = validate_configuration(get_settings())
        log.info(f"Configuration validated successfully")
        
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
            connection_timeout=conf.get('DB_CONNECTION_TIMEOUT', 30)
        )
        
        # Load model and check dependencies
        log.info("Checking dependencies and loading global model...")
        dependency_status = check_dependencies()
        
        # Fail fast if critical dependencies are not available
        if not dependency_status['model_loaded']:
            raise RuntimeError("Failed to load AI model - cannot continue")
            
        if not dependency_status['disk_writable']:
            raise RuntimeError("Critical directories are not writable - cannot continue")
        
        # Load global model with retry for robustness
        load_global_model_with_retry = retry(
            max_attempts=3,
            delay=2.0,
            backoff=2.0,
            exceptions=(Exception,)
        )(load_global_model)
        
        try:
            load_global_model_with_retry()
        except Exception as e:
            error_id = log_error_with_context(e, {"context": "model_loading"})
            raise RuntimeError(f"Failed to load global model after retries (ID: {error_id}): {e}")
        
        # Initialize health status
        update_health_file(health_check_file, "starting", {
            "dependencies": dependency_status
        })
        
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
            error_id = log_error_with_context(e, {"context": "inotify_setup", "path": stream_data_path})
            raise RuntimeError(f"Failed to set up inotify watch (ID: {error_id}): {e}")

        # Set up processing state with recovery
        processed_files_from_recovery, queue_items_from_recovery = load_processing_state(recovery_file)
        
        log.info("Getting backlog of WAV files...")
        backlog = get_wav_files()
        
        # Track processed files to avoid race conditions (with thread safety)
        processed_files = set()
        with processed_files_lock:
            for file in backlog:
                sanitized = sanitize_path(file, base_dir, strict=path_validation_strict)
                if sanitized:
                    processed_files.add(sanitized)
            
            # Add recovered files to processed set
            for file in processed_files_from_recovery:
                sanitized = sanitize_path(file, base_dir, strict=path_validation_strict)
                if sanitized:
                    processed_files.add(sanitized)
        
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
                            if validate_wav_file(sanitized, conf=conf):
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
                            error_id = log_error_with_context(e, {"context": "legacy_backlog", "file": file_name})
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
                                if validate_wav_file(sanitized, conf=conf):
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
                                error_id = log_error_with_context(e, {"context": "backlog_processing"})
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
        processed_files_limit = conf['PROCESSED_FILES_MEMORY_LIMIT']
        
        log.info("Starting main monitoring loop")
        for event in i.event_gen():
            if shutdown:
                log.info("Shutdown signal received, exiting monitoring loop")
                break
            
            # Periodically update health
            current_time = time.time()
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
                
                processed_files.add(file_path)
                
                # Limit the size of processed_files to prevent memory growth
                if len(processed_files) > processed_files_limit:
                    # Keep only the most recent entries
                    processed_files = set(list(processed_files)[-processed_files_limit//2:])
                    log.info(f"Trimmed processed_files memory to {len(processed_files)} entries")
            
            # Check for system overload and throttle if needed
            if is_system_overloaded(conf):
                overload_delay = conf['OVERLOAD_DELAY']
                log.info(f"System load high, throttling for {overload_delay} seconds")
                time.sleep(overload_delay)
            
            # Validate file before processing
            if not validate_wav_file(file_path, conf=conf):
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
                error_id = log_error_with_context(e, {"context": "main_loop_processing", "file": file_path})
                log.error(f"Error processing file (ID: {error_id}): {e}")
                
            empty_count = 0

        # Update health status to stopping
        update_health_file(health_check_file, "stopping", {
            "queue_size": report_queue.qsize() if not report_queue.empty() else 0,
            "processed_files": global_stats['processed_count'],
            "error_count": global_stats['error_count'],
            "skipped_count": global_stats['skipped_count'],
            "uptime_seconds": int(time.time() - global_stats['start_time'])
        })

        # Signal to the thread we're done
        log.info("Waiting for reporting queue to complete...")
        report_queue.put(None)
        
        # Wait with timeout to prevent deadlock
        thread_timeout = conf['THREAD_JOIN_TIMEOUT']
        thread.join(timeout=thread_timeout)
        if thread.is_alive():
            log.warning(f"Reporting thread did not exit cleanly within {thread_timeout}s timeout")
        
        try:
            # Allow some time for queue to process remaining items
            queue_join_timeout = conf['QUEUE_JOIN_TIMEOUT']
            queue_timeout = time.time() + queue_join_timeout
            while not report_queue.empty() and time.time() < queue_timeout:
                log.info(f"Waiting for queue to empty: {report_queue.qsize()} items remaining")
                time.sleep(1.0)
        except Exception as e:
            log.warning(f"Could not verify queue completion: {e}")
        
        # Clean up database connections
        if db_connection_pool is not None:
            try:
                db_connection_pool.close_all()
            except Exception as e:
                log.warning(f"Error closing database connections: {e}")
        
        # Final health update
        update_health_file(health_check_file, "stopped", {
            "queue_size": 0,
            "processed_files": global_stats['processed_count'],
            "error_count": global_stats['error_count'],
            "skipped_count": global_stats['skipped_count'],
            "uptime_seconds": int(time.time() - global_stats['start_time'])
        })
        
        # Final status log
        runtime = time.time() - global_stats['start_time']
        log.info(f"BirdNet analysis completed successfully after {runtime:.1f}s")
        log.info(f"Stats: processed={global_stats['processed_count']}, "
                f"errors={global_stats['error_count']}, "
                f"skipped={global_stats['skipped_count']}, "
                f"corrupt={global_stats.get('corrupt_files_detected', 0)}, "
                f"timeouts={global_stats.get('timeouts', 0)}")
        
    except Exception as e:
        error_id = log_error_with_context(e, {"context": "main_execution"})
        log.error(f"Fatal error (ID: {error_id}): {e}")
        
        # Update health file to indicate error
        update_health_file(health_check_file, "error", {
            "error_id": error_id,
            "error_type": e.__class__.__name__,
            "error_message": str(e)
        })
        
        sys.exit(1)


def process_file(file_name, report_queue, conf, base_dir=None):
    """Process a single audio file for bird detection
    
    Args:
        file_name (str): Path to the audio file
        report_queue (Queue): Queue for reporting results
        conf (dict): Configuration dictionary
        base_dir (str, optional): Base directory for path validation
    """
    context = {"file": os.path.basename(file_name)}
    file_size_warning_mb = conf.get('FILE_SIZE_WARNING_THRESHOLD_MB', 100)
    path_validation_strict = conf.get('PATH_VALIDATION_STRICT', True)
    analysis_timeout = conf.get('ANALYSIS_TIMEOUT', 300)  # Default 5 minutes timeout
    
    try:
        # Sanitize path
        file_name = sanitize_path(file_name, base_dir, strict=path_validation_strict)
        if not file_name:
            log.warning(f"Skipping file with invalid path")
            return
            
        if not os.path.exists(file_name):
            log.warning(f"File doesn't exist: {file_name}")
            return
            
        # Check file size before processing
        try:
            file_size = os.path.getsize(file_name)
            if file_size == 0:
                log.info(f"Removing empty file: {file_name}")
                try:
                    os.remove(file_name)
                except (OSError, PermissionError) as e:
                    log.warning(f"Could not remove empty file {file_name}: {e}")
                return
                
            # Add file size to context for better error reporting
            context["file_size"] = file_size
                
            # Check for suspiciously large files
            if file_size > file_size_warning_mb * 1024 * 1024:  # Warning threshold
                log.warning(f"File is unusually large ({file_size/1024/1024:.1f} MB): {file_name}")
        except Exception as size_err:
            log.warning(f"Could not check file size: {size_err}")
            
        log.info('Analyzing %s', file_name)
        
        try:
            # Mark file as being analyzed
            with open(ANALYZING_NOW, 'w') as analyzing:
                analyzing.write(file_name)
                
            file = ParseFileName(file_name)
            
            # Check if we should throttle based on system load
            if is_system_overloaded(conf):
                throttle_delay = conf['ANALYSIS_THROTTLE_DELAY']
                log.info(f"System load high during analysis, throttling for {throttle_delay}s")
                time.sleep(throttle_delay)
            
            # Run the analysis with timeout
            analysis_start_time = time.time()
            
            try:
                # Use ThreadPoolExecutor for timeout
                with ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(run_analysis, file)
                    try:
                        detections = future.result(timeout=analysis_timeout)
                    except TimeoutError:
                        # Handle timeout
                        log.error(f"Analysis timeout after {analysis_timeout}s for file: {file.file_name}")
                        with global_stats_lock:
                            global_stats['timeouts'] = global_stats.get('timeouts', 0) + 1
                        if HAS_PROMETHEUS:
                            TIMEOUT_COUNT.inc()
                        raise RuntimeError(f"Analysis timed out after {analysis_timeout}s")
            except RuntimeError as e:
                # Re-raise timeout errors
                raise e
            except Exception as e:
                # Catch and log other errors in the analysis function
                log.error(f"Error in run_analysis: {e}")
                raise e
                    
            analysis_duration = time.time() - analysis_start_time
            
            # Track slow analyses
            if analysis_duration > 60:  # More than 1 minute is considered slow
                with global_stats_lock:
                    global_stats['slow_analyses'] = global_stats.get('slow_analyses', 0) + 1
            
            # Update metrics
            if HAS_PROMETHEUS:
                ANALYSIS_DURATION.observe(analysis_duration)
            
            # Log analysis results
            detection_count = len(detections) if detections else 0
            log.info(f"Analysis complete: {detection_count} detections in {analysis_duration:.2f}s")
            
            # Add to context for better error reporting
            context.update({
                "detection_count": detection_count,
                "analysis_duration": f"{analysis_duration:.2f}s"
            })
            
            # Safely add to queue with timeout to prevent deadlock
            timeout = conf['QUEUE_TIMEOUT']
            try:
                # Add to queue with timeout to prevent deadlock
                report_queue.put((file, detections), timeout=timeout)
                if HAS_PROMETHEUS:
                    QUEUE_SIZE.set(report_queue.qsize())
            except Exception as e:
                log.error(f"Failed to add to queue (likely full): {e}")
                # Save to temporary file for later processing
                recovery_dir = conf['RECOVERY_DIR']
                try:
                    os.makedirs(recovery_dir, exist_ok=True)
                    recovery_file = os.path.join(
                        recovery_dir, 
                        f"recovery_{int(time.time())}_{os.path.basename(file_name)}.json"
                    )
                    
                    # Use atomic write for reliability
                    atomic_write_json({
                        "file_name": file.file_name,
                        "timestamp": time.time(),
                        "detection_count": len(detections)
                    }, recovery_file)
                    
                    log.info(f"Saved analysis results to recovery file: {recovery_file}")
                except Exception as save_err:
                    error_id = log_error_with_context(save_err, {"context": "recovery_save"})
                    log.error(f"Failed to save recovery file (ID: {error_id}): {save_err}")
            
        finally:
            # Clean up ANALYZING_NOW file
            try:
                if os.path.exists(ANALYZING_NOW):
                    with open(ANALYZING_NOW, 'w') as analyzing:
                        analyzing.write('')
            except Exception as e:
                log.warning(f"Error clearing ANALYZING_NOW file: {e}")
                
    except (KeyboardInterrupt, SystemExit):
        raise  # Let these pass through for proper shutdown
    except Exception as e:
        error_id = log_error_with_context(e, context)
        stderr = getattr(e, 'stderr', b'').decode('utf-8') if isinstance(e, CalledProcessError) else ""
        log.exception(f'Error processing file {file_name} (ID: {error_id}): {stderr}', exc_info=e)
        raise  # Re-raise to be handled by the caller


def handle_reporting_queue(queue, conf):
    """Handle the queue of files to be reported
    
    Args:
        queue (Queue): Queue of files to report
        conf (dict): Configuration dictionary
    """
    # Initialize circuit breakers for external services
    db_circuit = CircuitBreaker("database", 
                               failure_threshold=conf['DB_FAILURE_THRESHOLD'],
                               reset_timeout=conf['DB_RESET_TIMEOUT'])
    
    apprise_circuit = CircuitBreaker("apprise",
                                    failure_threshold=conf['APPRISE_FAILURE_THRESHOLD'],
                                    reset_timeout=conf['APPRISE_RESET_TIMEOUT'])
    
    weather_circuit = CircuitBreaker("bird_weather",
                                   failure_threshold=conf['WEATHER_FAILURE_THRESHOLD'],
                                   reset_timeout=conf['WEATHER_RESET_TIMEOUT'])
    
    # Add circuit breakers to global stats for monitoring
    with global_stats_lock:
        global_stats['circuit_breakers'] = {
            'database': db_circuit.get_stats(),
            'apprise': apprise_circuit.get_stats(),
            'bird_weather': weather_circuit.get_stats()
        }
    
    max_retries = conf['MAX_REPORTING_RETRIES']  # Retry mechanism for robustness
    retry_delay = conf['RETRY_DELAY']  # Seconds between retries
    
    # Setup processing stats
    processed_count = 0
    error_count = 0
    last_status_log = time.time()
    status_interval = conf['STATUS_LOG_INTERVAL']
    
    while True:
        try:
            # Log periodic status
            current_time = time.time()
            if current_time - last_status_log > status_interval:
                # Update circuit breaker stats in global stats with thread safety
                with global_stats_lock:
                    global_stats['circuit_breakers'] = {
                        'database': db_circuit.get_stats(),
                        'apprise': apprise_circuit.get_stats(),
                        'bird_weather': weather_circuit.get_stats()
                    }
                
                log.info(f"Reporting queue stats: processed={processed_count}, errors={error_count}, " +
                         f"queue_size={queue.qsize()}, " +
                         f"db_circuit={'open' if db_circuit.open else 'closed'}, " +
                         f"apprise_circuit={'open' if apprise_circuit.open else 'closed'}, " +
                         f"weather_circuit={'open' if weather_circuit.open else 'closed'}")
                last_status_log = current_time
                
            # Use timeout to periodically check for shutdown
            try:
                msg = queue.get(timeout=1.0)
            except Empty:
                if shutdown or shutdown_event.is_set():
                    break
                continue
                
            # Check for signal that we are done
            if msg is None:
                queue.task_done()
                break

            file, detections = msg
            
            # Process with retry logic
            for attempt in range(max_retries):
                try:
                    context = {
                        "file": os.path.basename(file.file_name),
                        "attempt": attempt + 1,
                        "detection_count": len(detections)
                    }
                    
                    # Update JSON file (always try this, it's local)
                    try:
                        update_json_file(file, detections)
                    except Exception as json_err:
                        log.warning(f"Error updating JSON file: {json_err}")
                    
                    for detection in detections:
                        # Extract detection (always try this, it's local)
                        try:
                            detection.file_name_extr = extract_detection(file, detection)
                            log.info('%s;%s', summary(file, detection), os.path.basename(detection.file_name_extr))
                        except Exception as extract_err:
                            log.warning(f"Error extracting detection: {extract_err}")
                            # Continue with other operations even if extraction fails
                        
                        # Write to file (always try this, it's local)
                        try:
                            write_to_file(file, detection)
                        except Exception as file_err:
                            log.warning(f"Error writing to file: {file_err}")
                            # Continue with other operations even if file write fails
                        
                        # Write to DB if circuit is closed
                        if db_circuit.can_execute():
                            try:
                                # Get a database connection from the pool
                                connection = None
                                try:
                                    connection = db_connection_pool.get_connection()
                                    # Call write_to_db with the connection
                                    write_to_db(file, detection, connection)
                                    db_circuit.record_success()
                                finally:
                                    # Always return the connection to the pool
                                    if connection is not None:
                                        db_connection_pool.release_connection(connection)
                            except Exception as db_err:
                                db_circuit.record_failure()
                                log.warning(f"DB write error: {db_err} - Circuit breaker active: {db_circuit.open}")
                                # Don't re-raise, continue with other operations
                    
                    # Apprise notification if circuit is closed
                    if apprise_circuit.can_execute():
                        try:
                            apprise(file, detections)
                            apprise_circuit.record_success()
                        except Exception as apprise_err:
                            apprise_circuit.record_failure()
                            log.warning(f"Apprise error: {apprise_err} - Circuit breaker active: {apprise_circuit.open}")
                    
                    # Weather reporting if circuit is closed
                    if weather_circuit.can_execute():
                        try:
                            bird_weather(file, detections)
                            weather_circuit.record_success()
                        except Exception as weather_err:
                            weather_circuit.record_failure()
                            log.warning(f"Weather error: {weather_err} - Circuit breaker active: {weather_circuit.open}")
                    
                    # Heartbeat (lightweight, always try)
                    try:
                        heartbeat()
                    except Exception as hb_err:
                        log.warning(f"Heartbeat error: {hb_err}")
                    
                    # Only remove file if processing succeeds
                    if os.path.exists(file.file_name):
                        try:
                            os.remove(file.file_name)
                        except (OSError, PermissionError) as e:
                            log.warning(f"Could not remove file {file.file_name}: {e}")
                    
                    # Count success
                    processed_count += 1
                    break  # Exit retry loop on success
                    
                except Exception as e:
                    error_id = log_error_with_context(e, context)
                    stderr = getattr(e, 'stderr', b'').decode('utf-8') if isinstance(e, CalledProcessError) else ""
                    
                    if attempt < max_retries - 1:
                        log.warning(f'Reporting error (ID: {error_id}) (attempt {attempt+1}/{max_retries}): {stderr}. Retrying in {retry_delay}s...')
                        time.sleep(retry_delay * (attempt + 1))  # Exponential backoff
                    else:
                        log.exception(f'Failed to report after {max_retries} attempts (ID: {error_id}): {stderr}', exc_info=e)
                        error_count += 1
            
            queue.task_done()
            
        except Exception as e:
            error_id = log_error_with_context(e)
            log.exception(f'Unexpected error in reporting thread (ID: {error_id}): {e}')
            error_count += 1
            # Always mark task as done to avoid queue getting stuck
            if 'msg' in locals() and msg is not None:
                queue.task_done()

    # Update final stats with thread safety
    with global_stats_lock:
        global_stats['reporting_processed'] = processed_count
        global_stats['reporting_errors'] = error_count
    
    log.info(f'handle_reporting_queue done - processed {processed_count} files with {error_count} errors')


def setup_logging():
    """Set up enhanced logging with rotation and formatting options"""
    conf = get_settings()
    logger = logging.getLogger()
    
    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    log_level_str = conf.get('LOG_LEVEL', 'INFO')
    log_format = conf.get('LOG_FORMAT', 'standard')
    
    # Convert log level string to actual level
    log_level = getattr(logging, log_level_str.upper(), logging.INFO)
    
    if log_format.lower() == 'json':
        # JSON structured logging for better parsing
        class JsonFormatter(logging.Formatter):
            def format(self, record):
                log_data = {
                    'timestamp': self.formatTime(record),
                    'level': record.levelname,
                    'name': record.name,
                    'message': record.getMessage(),
                    'process': record.process,
                    'thread': record.thread,
                    'thread_name': record.threadName
                }
                if record.exc_info:
                    log_data['exception'] = self.formatException(record.exc_info)
                return json.dumps(log_data)
        formatter = JsonFormatter()
    else:
        # Standard logging with more context
        formatter = logging.Formatter(
            "[%(asctime)s][%(name)s][%(levelname)s][%(process)d][%(threadName)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    
    # File handler with rotation
    if conf.get('LOG_TO_FILE', 'false').lower() == 'true':
        log_file = conf.get('LOG_FILE', '/var/log/birdnet/analysis.log')
        log_dir = os.path.dirname(log_file)
        
        # Create log directory if it doesn't exist
        try:
            os.makedirs(log_dir, exist_ok=True)
        except Exception as e:
            print(f"Warning: Could not create log directory {log_dir}: {e}")
            # Fall back to /tmp if we can't create the specified directory
            log_file = f"/tmp/birdnet_analysis_{int(time.time())}.log"
            print(f"Falling back to {log_file}")
        
        try:
            file_handler = RotatingFileHandler(
                log_file,
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            print(f"Warning: Could not set up file logging: {e}")
    
    # Console handler
    console_handler = logging.StreamHandler(stream=sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Set log level
    logger.setLevel(log_level)
    
    global log
    log = logging.getLogger('birdnet_analysis')


if __name__ == '__main__':
    # Register signal handlers first
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    # Setup logging
    setup_logging()

    try:
        main()
    except Exception as e:
        error_id = log_error_with_context(e, {"context": "main_execution"})
        log.error(f"Fatal error (ID: {error_id}): {e}")
        sys.exit(1)
