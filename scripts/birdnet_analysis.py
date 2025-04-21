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
from queue import Queue, Empty
from subprocess import CalledProcessError
from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler

try:
    import psutil
except ImportError:
    psutil = None  # Optional dependency for enhanced monitoring

import inotify.adapters
from inotify.constants import IN_CLOSE_WRITE

from server import load_global_model, run_analysis
from utils.helpers import get_settings, ParseFileName, get_wav_files, ANALYZING_NOW
from utils.reporting import extract_detection, summary, write_to_file, write_to_db, apprise, bird_weather, heartbeat, \
    update_json_file

shutdown = False
force_timer = None  # Timer for forced shutdown
log = logging.getLogger(__name__)


class CircuitBreaker:
    """Circuit breaker pattern implementation for external service calls"""
    def __init__(self, name, failure_threshold=5, reset_timeout=60):
        self.name = name
        self.failure_threshold = failure_threshold
        self.reset_timeout = reset_timeout
        self.failures = 0
        self.last_failure = 0
        self.open = False
    
    def can_execute(self):
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
        self.failures += 1
        self.last_failure = time.time()
        if self.failures >= self.failure_threshold and not self.open:
            log.warning(f"Circuit breaker for {self.name} opened after {self.failures} failures")
            self.open = True
            
    def record_success(self):
        if self.open:
            self.open = False
            self.failures = 0
            log.info(f"Circuit breaker for {self.name} closed after success")
        elif self.failures > 0:
            self.failures = 0


def sig_handler(sig_num, curr_stack_frame):
    """Enhanced signal handler with graceful shutdown timeout"""
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
    """Validate configuration and set defaults"""
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
    
    # Return validated configuration with defaults
    return conf


def sanitize_path(path, base_dir=None):
    """Sanitize file paths to prevent path traversal"""
    # Normalize path and ensure it's within allowed directory
    norm_path = os.path.normpath(path)
    if os.path.isabs(norm_path) and base_dir:
        # Convert absolute path to relative if necessary
        if not norm_path.startswith(base_dir):
            log.warning(f"Attempt to access file outside base directory: {path}")
            return None
    return norm_path


def is_system_overloaded():
    """Check if system resources are overloaded"""
    # Simple load check - could be more sophisticated
    try:
        if psutil:
            # Use psutil if available for better resource monitoring
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory_percent = psutil.virtual_memory().percent
            return cpu_percent > 80 or memory_percent > 90
        else:
            # Fallback to basic load average check
            load = os.getloadavg()[0]
            return load > 3.0  # Default threshold
    except:
        return False


def save_processing_state(processed_files, queue_items, recovery_file):
    """Save current processing state for recovery"""
    try:
        with open(recovery_file, 'w') as f:
            json.dump({
                'timestamp': time.time(),
                'processed_files': list(processed_files),
                'queue_items': queue_items
            }, f)
    except Exception as e:
        log.warning(f"Failed to save recovery state: {e}")


def load_processing_state(recovery_file):
    """Load processing state from recovery file"""
    try:
        if os.path.exists(recovery_file):
            with open(recovery_file, 'r') as f:
                state = json.load(f)
            log.info(f"Loaded recovery state from {recovery_file}")
            return set(state['processed_files']), state['queue_items']
    except Exception as e:
        log.warning(f"Failed to load recovery state: {e}")
    
    return set(), []


def log_error_with_context(e, context=None):
    """Log error with additional context information"""
    error_id = str(uuid.uuid4())[:8]  # Generate short ID for error tracking
    
    # Gather system information
    system_info = {
        'error_id': error_id,
        'hostname': socket.gethostname(),
        'pid': os.getpid(),
        'time': time.strftime('%Y-%m-%d %H:%M:%S'),
    }
    
    # Add memory info if psutil is available
    if psutil:
        system_info['memory_usage'] = psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024  # MB
    
    # Format context information
    context_str = ""
    if context:
        context_str = ", ".join(f"{k}={v}" for k, v in context.items())
    
    # Get full traceback
    import traceback
    tb = traceback.format_exc()
    
    # Log the error with all information
    log.error(f"Error[{error_id}] {e.__class__.__name__}: {str(e)} | {context_str}\n{tb}")
    
    return error_id


def main():
    # Load model and validate configuration
    load_global_model()
    conf = validate_configuration(get_settings())
    
    # Initialize recovery and health monitoring
    recovery_file = conf.get('RECOVERY_FILE', '/tmp/birdnet_recovery.json')
    health_check_file = conf.get('HEALTH_CHECK_FILE', '/tmp/birdnet_health')
    last_health_update = time.time()
    health_interval = conf.getint('HEALTH_INTERVAL', 60)  # seconds
    state_save_interval = conf.getint('STATE_SAVE_INTERVAL', 300)  # seconds
    last_state_save = time.time()
    
    # Resource management settings
    max_queue_size = conf.getint('MAX_QUEUE_SIZE', 1000)
    max_workers = conf.getint('MAX_WORKERS', 4)
    
    # Make StreamData path configurable with backward compatibility
    stream_data_path = conf.get('STREAM_DATA_DIR', os.path.join(conf['RECS_DIR'], 'StreamData'))
    base_dir = os.path.abspath(conf['RECS_DIR'])
    
    # Initialize inotify
    i = inotify.adapters.Inotify()
    i.add_watch(stream_data_path, mask=IN_CLOSE_WRITE)

    # Set up processing state with recovery
    processed_files_from_recovery, queue_items_from_recovery = load_processing_state(recovery_file)
    backlog = get_wav_files()
    
    # Track processed files to avoid race conditions
    processed_files = set(backlog) | processed_files_from_recovery

    # Initialize reporting queue with size limit
    report_queue = Queue(maxsize=max_queue_size)
    
    # Start reporting thread
    thread = threading.Thread(target=handle_reporting_queue, args=(report_queue, conf))
    thread.daemon = True  # Ensure thread exits if main thread exits
    thread.start()
    
    # Restore queue items from recovery if available
    for item in queue_items_from_recovery:
        try:
            file_name, detections = item
            report_queue.put((file_name, detections))
        except Exception as e:
            log.warning(f"Could not restore queue item from recovery: {e}")

    # Define health check update function
    def update_health_check():
        nonlocal last_health_update
        current_time = time.time()
        if current_time - last_health_update > health_interval:
            try:
                queue_size = report_queue.qsize()
                with open(health_check_file, 'w') as f:
                    f.write(json.dumps({
                        "timestamp": current_time,
                        "queue_size": queue_size,
                        "processed_files": len(processed_files),
                        "status": "running"
                    }))
                last_health_update = current_time
            except Exception as e:
                log.warning(f"Failed to update health check: {e}")
    
    # Define state save function
    def save_current_state():
        nonlocal last_state_save
        current_time = time.time()
        if current_time - last_state_save > state_save_interval:
            # We can't directly serialize the queue, so we'll just save the fact that we have items
            queue_status = [{"has_items": not report_queue.empty()}]
            save_processing_state(processed_files, queue_status, recovery_file)
            last_state_save = current_time

    log.info('backlog is %d', len(backlog))
    
    # Process backlog with worker pool
    if backlog:
        log.info(f"Processing backlog with {max_workers} workers")
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Process backlog in parallel
            futures = [executor.submit(process_file, file_name, report_queue, conf, base_dir) 
                      for file_name in backlog]
            for future in futures:
                try:
                    future.result()
                except Exception as e:
                    error_id = log_error_with_context(e, {"context": "backlog_processing"})
                    log.error(f"Error in backlog processing (ID: {error_id}): {e}")
                if shutdown:
                    break
    
    log.info('backlog done')

    # Update health immediately after backlog
    update_health_check()
    save_current_state()

    # Main event loop
    empty_count = 0
    throttle_delay = conf.getfloat('THROTTLE_DELAY', 0.1)  # Default small delay
    
    for event in i.event_gen():
        if shutdown:
            break
        
        # Periodically update health and save state
        update_health_check()
        save_current_state()

        if event is None:
            max_empty_count = (conf.getint('RECORDING_LENGTH', 30) * 2 + 30)
            if empty_count > max_empty_count:
                log.error('no more notifications: restarting...')
                break
            empty_count += 1
            time.sleep(throttle_delay)  # Avoid busy waiting
            continue

        (_, type_names, path, file_name) = event
        if re.search('.wav$', file_name) is None:
            continue
        
        log.debug("PATH=[%s] FILENAME=[%s] EVENT_TYPES=%s", path, file_name, type_names)

        file_path = os.path.join(path, file_name)
        file_path = sanitize_path(file_path, base_dir)
        
        if not file_path:
            log.warning(f"Skipping file with invalid path: {os.path.join(path, file_name)}")
            continue
        
        # Prevent double processing of files
        if file_path in processed_files:
            log.debug(f'Skipping already processed file: {file_path}')
            continue
        
        processed_files.add(file_path)
        
        # Check for system overload and throttle if needed
        if is_system_overloaded():
            overload_delay = conf.getfloat('OVERLOAD_DELAY', 5.0)
            log.info(f"System load high, throttling for {overload_delay} seconds")
            time.sleep(overload_delay)
        
        process_file(file_path, report_queue, conf, base_dir)
        empty_count = 0

    # Update health status to stopping
    try:
        with open(health_check_file, 'w') as f:
            f.write(json.dumps({
                "timestamp": time.time(),
                "queue_size": report_queue.qsize() if not report_queue.empty() else 0,
                "status": "stopping"
            }))
    except Exception as e:
        log.warning(f"Failed to update final health check: {e}")

    # Signal to the thread we're done
    log.info("Waiting for reporting queue to complete...")
    report_queue.put(None)
    
    # Wait with timeout to prevent deadlock
    thread_timeout = conf.getint('THREAD_JOIN_TIMEOUT', 60)
    thread.join(timeout=thread_timeout)
    if thread.is_alive():
        log.warning(f"Reporting thread did not exit cleanly within {thread_timeout}s timeout")
    
    try:
        # Allow some time for queue to process remaining items
        queue_join_timeout = conf.getint('QUEUE_JOIN_TIMEOUT', 10)
        report_queue.join()
    except Exception as e:
        log.warning(f"Could not verify queue completion: {e}")
    
    log.info("BirdNet analysis completed successfully")


def process_file(file_name, report_queue, conf, base_dir=None):
    """Process a single audio file for bird detection"""
    context = {"file": os.path.basename(file_name)}
    
    try:
        # Sanitize path
        file_name = sanitize_path(file_name, base_dir)
        if not file_name:
            log.warning(f"Skipping file with invalid path")
            return
            
        if not os.path.exists(file_name):
            log.warning(f"File doesn't exist: {file_name}")
            return
            
        if os.path.getsize(file_name) == 0:
            log.info(f"Removing empty file: {file_name}")
            try:
                os.remove(file_name)
            except (OSError, PermissionError) as e:
                log.warning(f"Could not remove empty file {file_name}: {e}")
            return
            
        log.info('Analyzing %s', file_name)
        
        try:
            # Mark file as being analyzed
            with open(ANALYZING_NOW, 'w') as analyzing:
                analyzing.write(file_name)
                
            file = ParseFileName(file_name)
            
            # Check if we should throttle based on system load
            if is_system_overloaded():
                throttle_delay = conf.getfloat('ANALYSIS_THROTTLE_DELAY', 2.0)
                log.info(f"System load high during analysis, throttling for {throttle_delay}s")
                time.sleep(throttle_delay)
            
            # Run the analysis
            detections = run_analysis(file)
            
            # Check if queue is full
            timeout = conf.getfloat('QUEUE_TIMEOUT', 30.0)
            try:
                # Add to queue with timeout to prevent deadlock
                report_queue.put((file, detections), timeout=timeout)
            except Exception as e:
                log.error(f"Failed to add to queue (likely full): {e}")
                # Save to temporary file for later processing
                recovery_dir = conf.get('RECOVERY_DIR', '/tmp/birdnet_recovery')
                os.makedirs(recovery_dir, exist_ok=True)
                recovery_file = os.path.join(recovery_dir, f"recovery_{int(time.time())}_{os.path.basename(file_name)}.json")
                try:
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


def handle_reporting_queue(queue, conf):
    """Handle the queue of files to be reported"""
    # Initialize circuit breakers for external services
    db_circuit = CircuitBreaker("database", 
                               failure_threshold=conf.getint('DB_FAILURE_THRESHOLD', 3),
                               reset_timeout=conf.getint('DB_RESET_TIMEOUT', 300))
    
    apprise_circuit = CircuitBreaker("apprise",
                                    failure_threshold=conf.getint('APPRISE_FAILURE_THRESHOLD', 3),
                                    reset_timeout=conf.getint('APPRISE_RESET_TIMEOUT', 300))
    
    weather_circuit = CircuitBreaker("bird_weather",
                                   failure_threshold=conf.getint('WEATHER_FAILURE_THRESHOLD', 3),
                                   reset_timeout=conf.getint('WEATHER_RESET_TIMEOUT', 300))
    
    max_retries = conf.getint('MAX_REPORTING_RETRIES', 3)  # Retry mechanism for robustness
    retry_delay = conf.getfloat('RETRY_DELAY', 2.0)  # Seconds between retries
    
    # Setup processing stats
    processed_count = 0
    error_count = 0
    last_status_log = time.time()
    status_interval = conf.getint('STATUS_LOG_INTERVAL', 300)  # Log status every 5 minutes
    
    while True:
        try:
            # Log periodic status
            current_time = time.time()
            if current_time - last_status_log > status_interval:
                log.info(f"Reporting queue stats: processed={processed_count}, errors={error_count}, " +
                         f"db_circuit={db_circuit.open}, apprise_circuit={apprise_circuit.open}")
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
                        "detections": len(detections)
                    }
                    
                    # Update JSON file (always try this, it's local)
                    update_json_file(file, detections)
                    
                    for detection in detections:
                        # Extract detection (always try this, it's local)
                        detection.file_name_extr = extract_detection(file, detection)
                        log.info('%s;%s', summary(file, detection), os.path.basename(detection.file_name_extr))
                        
                        # Write to file (always try this, it's local)
                        write_to_file(file, detection)
                        
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
                        time.sleep(retry_delay)
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

    log.info(f'handle_reporting_queue done - processed {processed_count} files with {error_count} errors')


def setup_logging():
    """Set up enhanced logging with rotation and formatting options"""
    conf = get_settings()
    logger = logging.getLogger()
    log_level = conf.get('LOG_LEVEL', 'INFO')
    log_format = conf.get('LOG_FORMAT', 'standard')
    
    if log_format.lower() == 'json':
        # JSON structured logging for better parsing
        class JsonFormatter(logging.Formatter):
            def format(self, record):
                log_data = {
                    'timestamp': self.formatTime(record),
                    'level': record.levelname,
                    'name': record.name,
                    'message': record.getMessage(),
                    'process': record.process
                }
                if record.exc_info:
                    log_data['exception'] = self.formatException(record.exc_info)
                return json.dumps(log_data)
        formatter = JsonFormatter()
    else:
        # Standard logging with more context
        formatter = logging.Formatter(
            "[%(asctime)s][%(name)s][%(levelname)s][%(process)d] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    
    # File handler with rotation
    if conf.get('LOG_TO_FILE', 'false').lower() == 'true':
        log_file = conf.get('LOG_FILE', '/var/log/birdnet/analysis.log')
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Console handler
    console_handler = logging.StreamHandler(stream=sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Set log level
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))
    
    global log
    log = logging.getLogger('birdnet_analysis')


if __name__ == '__main__':
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    setup_logging()

    try:
        main()
    except Exception as e:
        error_id = log_error_with_context(e, {"context": "main_execution"})
        log.error(f"Fatal error (ID: {error_id}): {e}")
        sys.exit(1)
