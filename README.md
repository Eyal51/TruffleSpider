# TruffleSpider
This spider scans a given URL for JS scripts, then using the entropy and regex engine and configuration from TruffleHog it scans for secrets.
The regex and entropy were borrowed from TruffleHof. Adaptation by Voxy


usage: trufflespider.py [-h] [--no-entropy | --no-regex] [--no-limit] url

positional arguments:
  url           the url to scan

optional arguments:
  -h, --help    show this help message and exit
  --no-entropy  do not search secrets by entropy
  --no-regex    do not search secrets by regex
  --no-limit    do not limit searching js files to the same domain
  
  
  #TODO:
  - allow searching in an individual file, either by link or locally
  - save run log to files
  
 
