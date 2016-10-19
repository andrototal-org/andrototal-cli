Andrototal-cli
--------------
Command line tool for analyzing apk on Android antiviruses.

**Requires:**

- adapers package 
- andropilot package
- avds (with the antivirus installed) inside HOME/.android/avd/

**Installation:**

- pip install andrototal-cli --process-dependency-links

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
