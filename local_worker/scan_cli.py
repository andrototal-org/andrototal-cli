"""
andrototal-cli
--------------
Command line tool for analyzing apk on Android antiviruses.

**Requires:**

- adapers package 
- andropilot package
- avds (with the antivirus installed) inside HOME/.android/avd/

**Installation:**

- pip install andrototal-cli

**Basic usage:**
andrototal-cli path/of/sample/apk NameOfTheAntivirus

**NameOfTheAntivirus:** 
one from the adapters package(there must exist and avd: name.of.the.antivirus inside HOME/.android/avd/)

**Example:** 
andrototal-cli malware.apk ComAntivirus

*usage*: andrototal-cli [-h] [-test-method {install,copy}]
                      [-log-level {DEBUG,INFO,WARNING,ERROR}]
                      [-window [WINDOW]] [-file-log FILE_LOG]
                      [-max-retries {1,2,3,4}]
                      [-store-device-data [STORE_DEVICE_DATA]]
                      malware_sample antivirus [antivirus ...]

*positional arguments*:
  malware_sample        path of the apk sample
  antivirus             name of the antivirus

*optional arguments*:

  -h, --help show this help message and exit

  -test-method {install,copy}, -t {install,copy}
                        test method
  -log-level {DEBUG,INFO,WARNING,ERROR}, -l {DEBUG,INFO,WARNING,ERROR}
                        logging level.
  -window [WINDOW], -w [WINDOW]
                        display emulator's graphical window
  -file-log FILE_LOG, -fl FILE_LOG
                        Redirect logger to file
  -max-retries {1,2,3,4}, -m {1,2,3,4}
                        maximum number of scan retries when a non fatal
                        exceptions occurs
  -store-device-data [STORE_DEVICE_DATA], -sd [STORE_DEVICE_DATA]
                        store device logcat and snapshot in device_data folder


**output:**



{
  'sample': {
    'sha256': '1944d8ee5bdda3a1bd06555fdb10d3267ab0cc4511d1e40611baf3ce1b81e5e8',

    'md5': '77b0105632e309b48e66f7cdb4678e02',

    'sha1': '4de0d8997949265a4b5647bb9f9d42926bd88191'

  },

  'test_count': 1,
  'success_count': 1,
  'tests': [

    {
      'status': 'SUCCESS',

      'ended_at': '2016-06-08 14:01:27',

      'detected_threat': 'THREAT_FOUND',

      'antivirus': 'ComAntivirus',

      'started_at': '2016-06-08 14:00:34',

      'analysis_time': 19

    }

  ],
  'failure_count': 0

}

"""





import sys
from core.utils import APKFileType, AVTypeAction
import logging
from core.task_manager import TaskManager
import logging.config

logger = logging.getLogger('andrototal')

logger.setLevel(logging.DEBUG)



try:
    import argparse
except ImportError:
    sys.stderr.write('You must either use Python 2.7 or install "argparse"\n')
    sys.exit(1)

test_methods = {
  'install' : 'detection_on_install',
  'copy' : 'detection_on_copy'
}


class ScanCli(object):
  def __call__(self):
    self._parse()
    self._config_logger()
    self._run_scan()

  def _parse(self):
    parser = argparse.ArgumentParser()

    parser.add_argument('malware_sample',
                        type=APKFileType,
                        help='path of the apk sample')

    parser.add_argument('antivirus',
                        nargs='+',
                        action=AVTypeAction,
                        help='name of the antivirus')

    parser.add_argument('-test-method',
                        '-t',
                        choices=['install',
                                'copy'],
                        help='test method',
                        default='install')
    
    parser.add_argument('-log-level',
                        '-l',
                        choices=['DEBUG',
                        'INFO',
                        'WARNING',
                        'ERROR'],
                        help='logging level.',
                        default='INFO')
    parser.add_argument('-window',
                        '-w',
                        nargs='?',
                        type=bool,
                        const=True,
                        help='display emulator\'s graphical window')
    
    parser.add_argument('-file-log',
                        '-fl',
                        type=str,
                        help='redirect logger to file',
                        )

    parser.add_argument('-max-retries',
                        '-m',
                        type=int,
                        choices=range(1,5),
                        help='maximum number of scan retries when a non fatal exceptions occurs',
                        default=1)
    
    parser.add_argument('-store-device-data',
                        '-sd',
                        nargs='?',
                        type=bool,
                        const=True,
                        help='store device logcat and snapshot in device_data folder')

    args = parser.parse_args()
    self.sample_path = args.malware_sample
    self.antivirus = args.antivirus
    self.test_method = test_methods[args.test_method]
    self.log_level = args.log_level
    self.window = args.window
    self.file_log = args.file_log
    self.max_retries = args.max_retries
    self.store_device_data = args.store_device_data

  
  def _config_logger(self):
    filename = (self.file_log if self.file_log else 'no_file_log')

    handler = ('console' if self.file_log is None else 'file')
    
    handler_dict = { 'console': {
                       'level': 'DEBUG',
                      'class': 'logging.StreamHandler',
                      'formatter': 'standard'
                },
                    "file": {
                      "level": "DEBUG",
                      "class": "logging.handlers.RotatingFileHandler",
                      "filename": filename,
                      "formatter": "standard",
                      "maxBytes": 104857600
                }
       }  

    logging.config.dictConfig({
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'standard': {
                    'format': '%(asctime)s [%(levelname)s] '
                    '%(name)s: %(message)s'
                },
            },
            'handlers': {
               handler : handler_dict[handler]     
            },
            'loggers': {
                'andrototal': {
                    'handlers': [handler],
                    'level': self.log_level,
                    'propagate': True
                }
            }
        })

  def _run_scan(self):
    logger.debug('Arguments received:\n\tsample: %s\n\tavs: %s\n\ttest_method %s' \
      % (self.sample_path, [av.av_name for av in self.antivirus], self. test_method))

    with TaskManager(self.sample_path, self.antivirus, self.test_method ,\
      self.window , self.max_retries, self.store_device_data) as tm:
      print tm.run()
      
def main():
  return ScanCli()()

if __name__ == '__main__':
  sys.exit(main())
