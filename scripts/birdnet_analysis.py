import logging
import os
import os.path
import re
import signal
import sys
import threading
import time
from queue import Queue, Empty
from subprocess import CalledProcessError

import inotify.adapters
from inotify.constants import IN_CLOSE_WRITE

from server import load_global_model, run_analysis
from utils.helpers import get_settings, ParseFileName, get_wav_files, ANALYZING_NOW
from utils.reporting import extract_detection, summary, write_to_file, write_to_db, apprise, bird_weather, heartbeat, \
    update_json_file

shutdown = False

log = logging.getLogger(__name__)


def sig_handler(sig_num, curr_stack_frame):
    global shutdown
    log.info('Caught shutdown signal %d', sig_num)
    shutdown = True


def main():
    load_global_model()
    conf = get_settings()
    # Make StreamData path configurable with backward compatibility
    stream_data_path = conf.get('STREAM_DATA_DIR', os.path.join(conf['RECS_DIR'], 'StreamData'))
    
    i = inotify.adapters.Inotify()
    i.add_watch(stream_data_path, mask=IN_CLOSE_WRITE)

    backlog = get_wav_files()
    # Track processed files to avoid race conditions
    processed_files = set(backlog)

    report_queue = Queue()
    thread = threading.Thread(target=handle_reporting_queue, args=(report_queue, ))
    thread.daemon = True  # Ensure thread exits if main thread exits
    thread.start()

    log.info('backlog is %d', len(backlog))
    for file_name in backlog:
        process_file(file_name, report_queue)
        if shutdown:
            break
    log.info('backlog done')

    empty_count = 0
    for event in i.event_gen():
        if shutdown:
            break

        if event is None:
            if empty_count > (conf.getint('RECORDING_LENGTH') * 2 + 30):
                log.error('no more notifications: restarting...')
                break
            empty_count += 1
            time.sleep(0.1)  # Avoid busy waiting
            continue

        (_, type_names, path, file_name) = event
        if re.search('.wav$', file_name) is None:
            continue
        log.debug("PATH=[%s] FILENAME=[%s] EVENT_TYPES=%s", path, file_name, type_names)

        file_path = os.path.join(path, file_name)
        
        # Prevent double processing of files
        if file_path in processed_files:
            log.debug(f'Skipping already processed file: {file_path}')
            continue
        
        processed_files.add(file_path)
        process_file(file_path, report_queue)
        empty_count = 0

    # Signal to the thread we're done
    log.info("Waiting for reporting queue to complete...")
    report_queue.put(None)
    
    # Wait with timeout to prevent deadlock
    thread.join(timeout=60)
    if thread.is_alive():
        log.warning("Reporting thread did not exit cleanly within timeout")
    
    try:
        # Allow some time for queue to process remaining items
        report_queue.join()
    except:
        log.warning("Could not verify queue completion")


def process_file(file_name, report_queue):
    try:
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
            detections = run_analysis(file)
            
            # Add to queue without waiting for processing
            report_queue.put((file, detections))
            
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
        stderr = getattr(e, 'stderr', b'').decode('utf-8') if isinstance(e, CalledProcessError) else ""
        log.exception(f'Error processing file {file_name}: {stderr}', exc_info=e)


def handle_reporting_queue(queue):
    max_retries = 3  # Add retry mechanism for robustness
    
    while True:
        try:
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
                    update_json_file(file, detections)
                    for detection in detections:
                        detection.file_name_extr = extract_detection(file, detection)
                        log.info('%s;%s', summary(file, detection), os.path.basename(detection.file_name_extr))
                        write_to_file(file, detection)
                        write_to_db(file, detection)
                    apprise(file, detections)
                    bird_weather(file, detections)
                    heartbeat()
                    
                    # Only remove file if processing succeeds
                    if os.path.exists(file.file_name):
                        try:
                            os.remove(file.file_name)
                        except (OSError, PermissionError) as e:
                            log.warning(f"Could not remove file {file.file_name}: {e}")
                    
                    break  # Exit retry loop on success
                except Exception as e:
                    stderr = getattr(e, 'stderr', b'').decode('utf-8') if isinstance(e, CalledProcessError) else ""
                    if attempt < max_retries - 1:
                        log.warning(f'Reporting error (attempt {attempt+1}/{max_retries}): {stderr}. Retrying...')
                        time.sleep(2)  # Wait before retry
                    else:
                        log.exception(f'Failed to report after {max_retries} attempts: {stderr}', exc_info=e)
            
            queue.task_done()
            
        except Exception as e:
            log.exception(f'Unexpected error in reporting thread: {e}')
            # Always mark task as done to avoid queue getting stuck
            if 'msg' in locals() and msg is not None:
                queue.task_done()

    log.info('handle_reporting_queue done')


def setup_logging():
    logger = logging.getLogger()
    formatter = logging.Formatter("[%(name)s][%(levelname)s] %(message)s")
    handler = logging.StreamHandler(stream=sys.stdout)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    global log
    log = logging.getLogger('birdnet_analysis')


if __name__ == '__main__':
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    setup_logging()

    main()
