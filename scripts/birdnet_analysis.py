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
from queue import Queue, Empty
from subprocess import CalledProcessError
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False  # Optional dependency for enhanced monitoring

import inotify.adapters
from inotify.constants import IN_CLOSE_WRITE

from server import load_global_model, run_analysis
from utils.helpers import get_settings, ParseFileName, get_wav_files, ANALYZING_NOW
from utils.reporting import extract_detection, summary, write_to_file, write_to_db, apprise, bird_weather, heartbeat, \
    update_json_file

# Global variables
shutdown = False
force_timer = None  # Timer for forced shutdown
log = logging.getLogger(__name__)
SCRIPT_VERSION = "1.2.1"  # Version tracking for logging

# Statistics tracking
global_stats = {
    "processed_count": 0,
    "error_count": 0,
    "skipped_count": 0,
    "start_time": 0,
    "backlog_size": 0,
    "circuit_breakers": {}
}


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
    
    def can_execute(self):
        """Check if the protected operation can be executed
        
        Returns:
            bool: True if circuit is closed or can be reset, False otherwise
        """
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
        self.failures += 1
        self.total_failures += 1
        self.last_failure = time.time()
        if self.failures >= self.failure_threshold and not self.open:
            log.warning(f"Circuit breaker for {self.name} opened after {self.failures} failures")
            self.open = True
            
    def record_success(self):
        """Record a success and potentially close the circuit"""
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
    global shutdown, force_timer
    log.info(f'Caught shutdown signal {sig_num}, initiating graceful shutdown')
    shutdown = True
    
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
                if isinstance(defaults[key], bool) or key.endswith('_STRICT') or key.startswith('LEGACY_'):
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
    # Memory threshold
    max_memory_percent = conf.get('MAX_MEMORY_PERCENT', 85)
    
    # Simple load check - could be more sophisticated
    try:
        if HAS_PSUTIL:
            # Use psutil if available for better resource monitoring
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory_percent = psutil.virtual_memory().percent
            disk_percent = psutil.disk_usage('/').percent
            
            # Add memory info to global stats
            if 'memory_usage' not in global_stats:
                global_stats['memory_usage'] = []
            
            # Keep last 10 memory readings
            memory_data = {
                'timestamp': time.time(),
                'memory_percent': memory_percent,
                'cpu_percent': cpu_percent,
                'disk_percent': disk_percent
            }
            global_stats['memory_usage'].append(memory_data)
            if len(global_stats['memory_usage']) > 10:
                global_stats['memory_usage'] = global_stats['memory_usage'][-10:]
            
            # Return True if any resource is critically high
            return (cpu_percent > 80 or 
                   memory_percent > max_memory_percent or 
                   disk_percent > 95)
        else:
            # Fallback to basic load average check
            load = os.getloadavg()[0]
            cpu_count = os.cpu_count() or 1
            return load > (cpu_count * 0.8)  # 80% of available CPUs
    except Exception as e:
        log.warning(f"Error checking system load: {e}")
        return False


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
        
        # Convert processed_files set to list and trim to reasonable size
        processed_list = list(processed_files)
        if len(processed_list) > 1000:
            processed_list = processed_list[-1000:]
        
        with open(recovery_file, 'w') as f:
            json.dump({
                'timestamp': time.time(),
                'version': SCRIPT_VERSION,
                'processed_files': processed_list,
                'queue_items': queue_items,
                'stats': {
                    'processed_count': global_stats.get('processed_count', 0),
                    'error_count': global_stats.get('error_count', 0),
                    'skipped_count': global_stats.get('skipped_count', 0),
                    'uptime': int(time.time() - global_stats.get('start_time', time.time()))
                }
            }, f)
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
                
            # Load stats
            if 'stats' in state:
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
    
    # Save error details to file for later analysis
    try:
        error_log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'logs', 'errors')
        os.makedirs(error_log_dir, exist_ok=True)
        
        error_file = os.path.join(error_log_dir, f"error_{error_id}_{int(time.time())}.json")
        with open(error_file, 'w') as f:
            json.dump({
                'error': {
                    'type': e.__class__.__name__,
                    'message': str(e),
                    'traceback': tb
                },
                'context': system_info
            }, f, indent=2)
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
        health_dir = os.path.dirname(health_file)
        # First check if directory exists before trying to create it
        if not os.path.exists(health_dir):
            try:
                os.makedirs(health_dir, exist_ok=True)
            except Exception as e:
                log.warning(f"Could not create health directory {health_dir}: {e}")
                # Try using /tmp as fallback
                health_file = f"/tmp/birdnet_health_{os.getpid()}"
        
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
                health_data.update({
                    "cpu_percent": psutil.cpu_percent(interval=0.1),
                    "memory_percent": psutil.virtual_memory().percent,
                    "disk_percent": psutil.disk_usage('/').percent
                })
            except Exception as e:
                health_data["stat_error"] = str(e)
        
        # Add stats from global stats
        for key in ["processed_count", "error_count", "skipped_count"]:
            if key in global_stats:
                health_data[key] = global_stats[key]
        
        # Add circuit breaker stats
        if 'circuit_breakers' in global_stats:
            health_data["circuit_breakers"] = global_stats['circuit_breakers']
        
        # Add extra info
        if extra_info:
            health_data.update(extra_info)
            
        # Handle atomicity by writing to temporary file first
        tmp_health_file = f"{health_file}.tmp"
        with open(tmp_health_file, 'w') as f:
            json.dump(health_data, f)
        
        # Atomic replace
        os.replace(tmp_health_file, health_file)
            
    except Exception as e:
        log.warning(f"Failed to update health check: {e}")


def main():
    """Main processing function for BirdNet analysis"""
    global_stats['start_time'] = time.time()
    log.info(f"Starting BirdNet Analysis v{SCRIPT_VERSION}")
    
    try:
        # Load model and validate configuration
        log.info("Loading global model...")
        load_global_model()
        
        conf = validate_configuration(get_settings())
        log.info(f"Configuration validated successfully")
        
        # Check for legacy mode
        legacy_mode = conf.get('LEGACY_MODE', False)
        if legacy_mode:
            log.info("Running in legacy compatibility mode")
        
        # Initialize recovery and health monitoring
        recovery_file = conf['RECOVERY_FILE']
        health_check_file = conf['HEALTH_CHECK_FILE']
        health_interval = conf['HEALTH_INTERVAL']
        state_save_interval = conf['STATE_SAVE_INTERVAL']
        
        # Initialize health status
        update_health_file(health_check_file, "starting")
        
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
        
        # Track processed files to avoid race conditions
        processed_files = set()
        for file in backlog:
            sanitized = sanitize_path(file, base_dir, strict=path_validation_strict)
            if sanitized:
                processed_files.add(sanitized)
        
        # Add recovered files to processed set
        for file in processed_files_from_recovery:
            sanitized = sanitize_path(file, base_dir, strict=path_validation_strict)
            if sanitized:
                processed_files.add(sanitized)
        
        # Update global stats
        global_stats['backlog_size'] = len(backlog)

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
                            process_file(sanitized, report_queue, conf, base_dir)
                            global_stats['processed_count'] += 1
                        except Exception as e:
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
                                futures.append(
                                    executor.submit(process_file, sanitized, report_queue, conf, base_dir)
                                )
                        
                        for idx, future in enumerate(futures):
                            try:
                                future.result()
                                global_stats['processed_count'] += 1
                            except Exception as e:
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
                update_health_file(health_check_file, "monitoring", {
                    "queue_size": report_queue.qsize(),
                    "processed_files": global_stats['processed_count'],
                    "error_count": global_stats['error_count'],
                    "skipped_count": global_stats['skipped_count'],
                    "uptime_seconds": int(current_time - global_stats['start_time']),
                    "recent_file_count": len(processed_files)
                })
                global_stats['last_health_update'] = current_time
            
            # Periodically save state
            if 'last_state_save' not in global_stats or current_time - global_stats['last_state_save'] > state_save_interval:
                save_processing_state(processed_files, [], recovery_file)
                global_stats['last_state_save'] = current_time

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
                global_stats['skipped_count'] += 1
                continue
            
            # Prevent double processing of files
            if file_path in processed_files:
                log.debug(f'Skipping already processed file: {file_path}')
                global_stats['skipped_count'] += 1
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
            
            # Process the file
            try:
                process_file(file_path, report_queue, conf, base_dir)
                global_stats['processed_count'] += 1
            except Exception as e:
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
                f"skipped={global_stats['skipped_count']}")
        
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
            
            # Run the analysis
            analysis_start_time = time.time()
            detections = run_analysis(file)
            analysis_duration = time.time() - analysis_start_time
            
            # Log analysis results
            detection_count = len(detections) if detections else 0
            log.info(f"Analysis complete: {detection_count} detections in {analysis_duration:.2f}s")
            
            # Add to context for better error reporting
            context.update({
                "detection_count": detection_count,
                "analysis_duration": f"{analysis_duration:.2f}s"
            })
            
            # Check if queue is full
            timeout = conf['QUEUE_TIMEOUT']
            try:
                # Add to queue with timeout to prevent deadlock
                report_queue.put((file, detections), timeout=timeout)
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
                    with open(recovery_file, 'w') as f:
                        # Can't directly serialize detection objects, so use their string representations
                        json.dump({
                            "file_name": file.file_name,
                            "timestamp": time.time(),
                            "detection_count": len(detections)
                        }, f)
                    log.info(f"Saved analysis results to recovery file: {recovery_file}")
                except Exception as save_err:
                    log.error(f"Failed to save recovery file: {save_err}")
            
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
                # Update circuit breaker stats in global stats
                global_stats['circuit_breakers'] = {
                    'database': db_circuit.get_stats(),
                    'apprise': apprise_circuit.get_stats(),
                    'bird_weather': weather_circuit.get_stats()
                }
                
                log.info(f"Reporting queue stats: processed={processed_count}, errors={error_count}, " +
                         f"db_circuit={'open' if db_circuit.open else 'closed'}, " +
                         f"apprise_circuit={'open' if apprise_circuit.open else 'closed'}, " +
                         f"weather_circuit={'open' if weather_circuit.open else 'closed'}")
                last_status_log = current_time
                
            # Use timeout to periodically check for shutdown
            try:
                msg = queue.get(timeout=1.0)
            except Empty:
                if shutdown:
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
                    update_json_file(file, detections)
                    
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
                                write_to_db(file, detection)
                                db_circuit.record_success()
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

    # Update final stats
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
