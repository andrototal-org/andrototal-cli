"""
this module contains the TaskManager class, which handles a queue of scans
of a given sample on one or more antiviruses.
"""



import os
from os.path import expanduser
import logging
import traceback
import json
from multiprocessing import Queue
from threading import Timer
import shutil
from adapters.base import ScanTimeout
import virtualdevice
import lockfile
from utils import import_test_by_name, pick_unused_port, get_hashes
from task import Task
from utils import DEVICES_DATA_DIR

logger = logging.getLogger('andrototal.task_manager')


class TaskManager(object):
  """
  the TaskManager object handles one or more scans for a malware sample
  on one or more antiviruses. 
  """

  def __enter__(self):
    return self

  def __exit__(self, type, value, traceback):
    self.ready_queue.close()
    self.retry_queue.close()
    if not self.store_logcat_snapshot:
      shutil.rmtree(DEVICES_DATA_DIR, ignore_errors=True)

  def __init__(self, sample_path, avs, test_method, window, max_retries, store_logcat_snapshot):
    self.tests = {}
    self.ready_queue = Queue()
    self.window = window
    self.sample_path = sample_path
    self.max_retries = max_retries
    self.store_logcat_snapshot = store_logcat_snapshot
    
    try:
      os.mkdir(DEVICES_DATA_DIR)
    except:
      pass
	#create a queue of tasks
    for av in avs:

      logger.debug('Creating task with av: %s, avd %s test_method: %s'% \
                    (av.av_name, av.avd_name, test_method))
      
      task_test_data = {
          'detection_method': test_method,
          'test_module_name': av.av_name,
          'avd_name' : av.avd_name }
      #get antivirus info from the json file inside the folder of the avd
      #Example com.antivirus.json
      antivirus_info = self._get_antivirus_info(av.avd_name)

      task = Task(sample_path, task_test_data, self.window, antivirus_info)
      self.ready_queue.put(task)


  def run(self):
    """
    run the scans for every antivirus
    each scan can be retried "max_retries" times when
    ScanTimeout, FileLockException or AVDStartTimeOut occurs.
	After "max_retries" attempts or when another exception occurs
    the scan will fail.
    When one of the retriable exception occurs (ScanTimeout, FileLockException 
    or AVDStartTimeOut) the retry will be delayed according to the values
	returned from "get_delays(ex_name)"

	:returns: dictionary with the result of each scan
    """

    result = {'sample' : get_hashes(self.sample_path),
              'test_count' : int(self.ready_queue.qsize()),
              'success_count' : 0,
              'tests': []
    }

    logger.debug('Scan queue of %d tests'% (self.ready_queue.qsize()))
    
	#retry_queue contains the task that must be retried
    self.retry_queue = Queue()
    while not self.ready_queue.empty() or not self.retry_queue.empty():
      
      
      task = self.ready_queue.get() 
      
      try:
         
        task_result = task.run()
        result['success_count'] = result['success_count'] + 1
        result['tests'].append(task_result)
      #catch exception that might be raised during the execution of the task
      except (ScanTimeout, lockfile.FileLockException, \
              virtualdevice.AVDStartTimeOut) as e:
        task.cleanup_files()

        if task.num_tries == self.max_retries:
          logger.debug('Scan on: %s failed after %d tries' % \
                       (task.test['test_module_name'], self.max_retries))
          task_id = (task.test['test_module_name'] 
                  + ', on ' + task.test['avd_name']
                  + ', with ' + task.sample_path
                  + ' for ' + task.test['detection_method'])

          result['tests'].append(task.failure(e.__class__.__name__,\
                      'Task %s failed after %d attempts' % (task_id,self.max_retries)))
          continue


        logger.debug('Retrying scan of %s with %s' % \
                        (self.sample_path, task.test['test_module_name']))

        self.retry_queue.put(task)

        delay = get_delay(e.__class__.__name__)
        t = Timer( delay, self._put_on_ready_queue, args=[task])
        t.setDaemon(True)
        t.start()

      except Exception as e:
        task.cleanup_files()

        logger.debug('Failed to scan %s with %s ' % \
                     (self.sample_path, task.test['test_module_name']), exc_info=True)
        tb = traceback.format_exc()
        result['tests'].append(task.failure(e.__class__.__name__, tb))
        
    result['failure_count'] = result['test_count'] - result['success_count']
    return result

  def _put_on_ready_queue(self,task):
    logger.debug('Task for %s back in queue' % task.test['test_module_name'])
    
    try: 
      self.retry_queue.get()
    except:
      pass
    
    self.ready_queue.put(task)
  
  #every avd must have a json file with informations about the installed
  #antivirus
  def _get_antivirus_info(self, avd_name):
    avd_dir = expanduser('~') + '/.android/avd'
    av_file = open(avd_dir + '/' + avd_name + '.avd/' + avd_name + '.json')
    av = json.load(av_file)
    av_file.close()
    return {
        "engine_version": av['engine_version'],
        "name": av['name'],
        "developer": av['developer']
      }

def get_delay(ex_name):
  """
  :return: a dictionary of delay values (in seconds) used for retriable exceptions of scans
  {'ScanTimeout' : 3, 'FileLockException' : 60, 'AVDStartTimeOut' : 30}
  """

  delay_values = {'ScanTimeout' : 3, 'FileLockException' : 60, 'AVDStartTimeOut' : 30}
  return delay_values[ex_name]
