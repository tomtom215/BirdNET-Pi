import logging
import os
import os.path
import re
import signal
import sys
import threading
import time
from contextlib import contextmanager
from queue import Queue, Empty
from subprocess import CalledProcessError

import inotify.adapters
from inotify.constants import IN_CLOSE_WRITE

from server import load_global_model, run_analysis
from utils.helpers import get_settings, ParseFileName, get_wav_files, ANALYZING_NOW
from utils.reporting import extract_detection, summary, write_to_file, write_to_db, apprise, bird_weather, heartbeat, \
    update_json_file

# Global variables
shutdown = False
log = logging.getLogger(__name__)

# Constants - extracted from hardcoded values for better configurability
DEFAULT_LOG_LEVEL = logging.INFO
WAV_FILE_PATTERN = re.compile(r'\.wav$')
MAX_QUEUE_SIZE = 100  # Maximum size for reporting queue
QUEUE_TIMEOUT = 30  # Seconds to wait for queue operations
HEARTBEAT_INTERVAL = 300  # Seconds between heartbeats


def sig_handler(sig_num, curr_stack_frame):
    """Handle termination signals and set the global shutdown flag."""
    global shutdown
    log.info('Caught shutdown signal %d', sig_num)
    shutdown = True


@contextmanager
def analyzing_file(file_name):
    """Context manager to track the file currently being analyzed.
    
    Args:
        file_name: Path to the file being analyzed
    """
    try:
        with open(ANALYZING_NOW, 'w') as analyzing:
            analyzing.write(file_name)
        yield
    finally:
        # Clean up the analyzing file when done or if an exception occurs
        if os.path.exists(ANALYZING_NOW):
            try:
                os.remove(ANALYZING_NOW)
            except OSError as e:
                log.warning(f"Failed to remove {ANALYZING_NOW}: {e}")


def safe_remove_file(file_path):
    """Safely remove a file, handling exceptions.
    
    Args:
        file_path: Path to the file to remove
    
    Returns:
        bool: True if successful, False otherwise
    """
    if not os.path.exists(file_path):
        return True
    
    try:
        os.remove(file_path)
        return True
    except OSError as e:
        log.warning(f"Failed to remove {file_path}: {e}")
        return False


def process_file(file_name, report_queue):
    """Process a WAV file for bird sound detection.
    
    Args:
        file_name: Path to the WAV file
        report_queue: Queue for reporting results
    """
    # Check if file exists before processing
    if not os.path.exists(file_name):
        log.warning(f"File {file_name} no longer exists")
        return
    
    # Check for empty files
    try:
        if os.path.getsize(file_name) == 0:
            log.info(f"Removing empty file {file_name}")
            safe_remove_file(file_name)
            return
    except OSError as e:
        log.warning(f"Failed to check size of {file_name}: {e}")
        return
    
    log.info('Analyzing %s', file_name)
    
    # Use context manager to ensure cleanup
    with analyzing_file(file_name):
        try:
            file = ParseFileName(file_name)
            detections = run_analysis(file)
            
            # Wait for previous reports to complete to maintain order
            # Add a timeout to prevent blocking indefinitely
            try:
                report_queue.join()
            except Exception as e:
                log.error(f"Error waiting for report queue: {e}")
            
            # Check shutdown flag before putting more work in the queue
            if not shutdown:
                try:
                    # Use a timeout to avoid blocking indefinitely if queue is full
                    report_queue.put((file, detections), timeout=QUEUE_TIMEOUT)
                except Exception as e:
                    log.error(f"Failed to add to report queue: {e}")
        except CalledProcessError as e:
            stderr = e.stderr.decode('utf-8') if hasattr(e, 'stderr') and e.stderr else ""
            log.exception(f'Process error during analysis: {stderr}', exc_info=e)
        except Exception as e:
            # More specific exception handling
            log.exception(f'Unexpected error during analysis: {e}', exc_info=e)


def handle_reporting_queue(queue):
    """Worker thread to process detection reports from the queue.
    
    Args:
        queue: Queue containing detection reports
    """
    last_heartbeat = time.time()
    
    while not shutdown:
        try:
            # Use a timeout to periodically check the shutdown flag
            try:
                msg = queue.get(timeout=5)
            except Empty:
                # Send periodic heartbeats even when idle
                if time.time() - last_heartbeat >= HEARTBEAT_INTERVAL:
                    try:
                        heartbeat()
                        last_heartbeat = time.time()
                    except Exception as e:
                        log.error(f"Failed to send heartbeat: {e}")
                continue
            
            # Check for signal that we are done
            if msg is None:
                queue.task_done()
                break
            
            file, detections = msg
            try:
                # Process the detection
                process_detection(file, detections)
                last_heartbeat = time.time()  # Reset heartbeat timer after successful processing
            except Exception as e:
                log.exception(f'Error processing detection for {file.file_name}: {e}', exc_info=e)
            finally:
                # Always mark task as done even if processing failed
                queue.task_done()
        
        except Exception as e:
            log.exception(f'Unexpected error in reporting queue handler: {e}', exc_info=e)
    
    log.info('Reporting queue handler shutting down')


def process_detection(file, detections):
    """Process detections for a file.
    
    Args:
        file: File object with metadata
        detections: List of detection objects
    """
    try:
        # Update JSON data first for status tracking
        update_json_file(file, detections)
        
        # Process each detection
        for detection in detections:
            try:
                detection.file_name_extr = extract_detection(file, detection)
                log.info('%s;%s', summary(file, detection), os.path.basename(detection.file_name_extr))
                
                # Write results to file and database
                write_to_file(file, detection)
                write_to_db(file, detection)
            except Exception as e:
                log.error(f"Error processing individual detection: {e}")
        
        # Send notifications
        try:
            apprise(file, detections)
        except Exception as e:
            log.error(f"Error sending notifications: {e}")
        
        try:
            bird_weather(file, detections)
        except Exception as e:
            log.error(f"Error updating bird weather data: {e}")
        
        try:
            heartbeat()
        except Exception as e:
            log.error(f"Error sending heartbeat: {e}")
        
        # Only remove the file if all processing completed successfully
        safe_remove_file(file.file_name)
    
    except Exception as e:
        stderr = e.stderr.decode('utf-8') if isinstance(e, CalledProcessError) and hasattr(e, 'stderr') and e.stderr else ""
        log.exception(f'Error in detection processing: {stderr}', exc_info=e)
        # Do not remove the file in case of processing errors


def setup_file_watcher(watch_dir, event_mask=IN_CLOSE_WRITE):
    """Set up a file watcher for the given directory.
    
    Args:
        watch_dir: Directory to watch
        event_mask: inotify event mask
        
    Returns:
        inotify.adapters.Inotify: Configured inotify instance
    """
    try:
        i = inotify.adapters.Inotify()
        i.add_watch(watch_dir, mask=event_mask)
        return i
    except Exception as e:
        log.error(f"Failed to set up file watcher for {watch_dir}: {e}")
        raise


def process_backlog(backlog, report_queue):
    """Process any existing files in the backlog.
    
    Args:
        backlog: List of file paths
        report_queue: Queue for reporting results
        
    Returns:
        int: Number of files processed
    """
    count = 0
    log.info('Processing backlog of %d files', len(backlog))
    
    for file_name in backlog:
        if shutdown:
            break
        
        process_file(file_name, report_queue)
        count += 1
    
    log.info('Backlog processing complete: %d/%d files processed', count, len(backlog))
    return count


def main():
    """Main function to run the bird sound detection system."""
    # Load the machine learning model
    try:
        load_global_model()
    except Exception as e:
        log.critical(f"Failed to load global model: {e}")
        return 1
    
    # Get configuration
    conf = get_settings()
    
    # Set up the stream data directory path
    stream_data_dir = os.path.join(conf['RECS_DIR'], 'StreamData')
    if not os.path.exists(stream_data_dir):
        log.error(f"Watch directory does not exist: {stream_data_dir}")
        return 1
    
    # Set up file watcher
    try:
        i = setup_file_watcher(stream_data_dir)
    except Exception as e:
        log.critical(f"Failed to set up file watcher: {e}")
        return 1
    
    # Get existing files
    backlog = get_wav_files()
    
    # Set up reporting queue and worker thread
    report_queue = Queue(maxsize=MAX_QUEUE_SIZE)
    reporter_thread = threading.Thread(
        target=handle_reporting_queue, 
        args=(report_queue,),
        name="ReportingThread",
        daemon=True  # Make thread daemon so it exits when main thread exits
    )
    reporter_thread.start()
    
    try:
        # Process existing files
        process_backlog(backlog, report_queue)
        
        # Clear backlog list to free memory
        backlog = []
        
        # Calculate max empty events based on configuration
        max_empty_events = (conf.getint('RECORDING_LENGTH', 30) * 2 + 30)
        empty_count = 0
        
        # Main event loop
        log.info("Starting file watch loop")
        for event in i.event_gen():
            if shutdown:
                log.info("Shutdown flag detected, exiting main loop")
                break
            
            # Handle empty events (timeouts)
            if event is None:
                empty_count += 1
                if empty_count > max_empty_events:
                    log.error('No inotify events received for too long: restarting...')
                    break
                time.sleep(0.1)  # Short sleep to avoid CPU spinning
                continue
            
            # Reset empty counter on any event
            empty_count = 0
            
            # Parse the event
            (_, type_names, path, file_name) = event
            
            # Only process WAV files
            if not WAV_FILE_PATTERN.search(file_name):
                continue
            
            log.debug("PATH=[%s] FILENAME=[%s] EVENT_TYPES=%s", path, file_name, type_names)
            
            # Build full file path
            file_path = os.path.join(path, file_name)
            
            # Process the new file
            process_file(file_path, report_queue)
    
    except Exception as e:
        log.exception(f"Unexpected error in main loop: {e}")
    
    finally:
        # Clean shutdown
        log.info("Shutting down, waiting for reporting queue to complete...")
        
        # Signal reporting thread to finish
        try:
            report_queue.put(None)
            
            # Wait for reporting thread with timeout
            reporter_thread.join(timeout=60)
            if reporter_thread.is_alive():
                log.warning("Reporting thread did not exit cleanly")
            
            # Wait for queue to be fully processed
            try:
                report_queue.join()
            except Exception as e:
                log.warning(f"Error waiting for queue to finish: {e}")
        
        except Exception as e:
            log.error(f"Error during shutdown: {e}")
    
    log.info("Application shutdown complete")
    return 0


def setup_logging():
    """Configure the logging system."""
    logger = logging.getLogger()
    
    # Clear any existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter("[%(asctime)s][%(name)s][%(levelname)s] %(message)s")
    
    # Set up console handler
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    # Set log level
    logger.setLevel(DEFAULT_LOG_LEVEL)
    
    # Set module-specific logger
    global log
    log = logging.getLogger('birdnet_analysis')


if __name__ == '__main__':
    # Register signal handlers
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)
    
    # Set up logging
    setup_logging()
    
    # Run main function
    sys.exit(main())
