#!/usr/bin/env python

"""
Copyright (c) 2012, Alexander Minges <alexander.minges@googlemail.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met: 

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer. 
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution. 

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""

### Adjust the following lines to your needs

# You may add more blacklist URLs:
# BLOCKLISTS            = ['http://www.list1.com', 'http://www.list2.com', 'http://www.list3.com']
BLOCKLISTS            = ['http://www.spamhaus.org/drop/drop.lasso']

NGINX_CONF_DIR        = '/etc/nginx'                  # Path to your nginx.conf
NGINX_DROP_CONF       = 'blocklist.conf'              # File that will hold the IP ranges to be blocked. 
                                                      # Be sure to add "include <Value of NGINX_DROP_CONF>" to your nginx.conf
NGINX_EXEC            = 'nginx'                       # Path to your nginx executable. No need to change, if it is in your PATH.
LOG_FILE              = '/var/log/nginx/nginx_bl.log' # Path to logfile. Make sure the user executing this script 
                                                      # has write permissions!
LOG_LEVEL_CONSOLE     = 'WARNING'                     # Allowed values: DEBUG, INFO, WARNING, ERROR, CRITICAL
                                                      # Recommended: WARNING
LOG_LEVEL_FILE        = 'INFO'                        # Allowed values: DEBUG, INFO, WARNING, ERROR, CRITICAL
                                                      # Recommended: INFO

### Don't change anything below unless you know what you're doing!

import sys
import os
import logging
import re

from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError
from subprocess import check_call, CalledProcessError

class CIDRValidator:
  """
  Class for CIDR validation. This way we're efficiently reusing the regex objects.
  """
  def __init__(self): 
    """
    Compiling regex objects
    """
    self.cidr_ipv4_re = re.compile(r"""^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}
                                   ([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])
                                   (\/(\d|[1-2]\d|3[0-2]))""", re.VERBOSE)
    self.cidr_ipv6_re = re.compile(r"""^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|
                                   (([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|
                                   ((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|
                                   (([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)
                                   (\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|
                                   ((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|
                                   (([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|
                                   ((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|
                                   [1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|
                                   ((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))
                                   {3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:
                                   ((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4})
                                   {1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d))
                                   {3}))|:)))(%.+)?\s*(\/(\d|\d\d|1[0-1]\d|12[0-8]))""", re.VERBOSE)

  def validate(self, ip_cidr):
    """
    Check if we are dealing with a valid CIDR range and return only valid CIDR values.
    """
    if self.cidr_ipv4_re.match(ip_cidr):                # Check for valid IPv4 CIDR
      return self.cidr_ipv4_re.match(ip_cidr).group(0)
    elif self.cidr_ipv6_re.match(ip_cidr):              # Check for valid IPv6 CIDR
      return self.cidr_ipv6_re.match(ip_cidr).group(0)
    else:
      return False

def setupLogHandler():
  """
  Setup handler for logging. We are logging to console and to a logfile with seperate
  logging levels.
  """

  # Adding two logfile handlers. The first is logging to a logfile, the second to the stdout.
  try: # Catch errors while opening the logfile in writing mode
    logging.basicConfig(filename='%s' % LOG_FILE,
                        level=getNumLoglevel(LOG_LEVEL_FILE),
                        format='%(levelname)-8s: %(asctime)s %(message)s',
                        datefmt='%y-%m-%d %H:%M')
                                
  except OSError as e:
    print('Failed to open logfile for writing: %s' % e)
  except:
    print('Unknown error while opening logfile for writing!')
  else: # Setup logging to console
    console = logging.StreamHandler()
    formatter = logging.Formatter(fmt='%(levelname)-8s: %(asctime)s %(message)s',
                                  datefmt='%y-%m-%d %H:%M')
    console.setLevel(getNumLoglevel(LOG_LEVEL_CONSOLE))
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)


def getNumLoglevel(level):
  """
  Convert loglevel string to numeric value that can be passed to the logfile handler.
  Fails if invalid log value is given.
  """
  level_num = getattr(logging, level.upper().strip(), None)
  if not isinstance(level_num, int):
    raise ValueError('Invalid log level: %s' % level)
  else:
    return level_num
    
def checkUrl(url):
  """
  Very basic sanity check of the URL. Succeeds if starting with "http://"
  """
  u = urlparse(url)
  if getattr(u, 'scheme') in ('http://'): # parse URL and check if it is starting with http://
    return True
  else:
    return False

def getFile(url):
  """
  Returns a file object from the given URL. Catches server side 
  errors (file not found etc.)
  """
  if checkUrl(url): # Do sanity check for url
    logging.info('Loading blocklist from %s' % url)
    try:
      response = urlopen(url)
    except URLError as e: # Catch server side errors
      if hasattr(e, 'reason'):
        logging.critical('Failed to reach server: %s' % e.reason)
      elif hasattr(e, 'code'):
        logging.critical('Server responded with HTTP error code: %s' % e.code)
    else:
      return response
  else: # Throw exception if sanity check fails
    msg = '\"%s\" not well-formed. Expecting \"http://\" at the beginning!' % url
    logging.critical(msg)
    raise URLError(msg)    
  
def collectBlockedIps():
  """
  Generates a list of unique IP ranges to be blocked. Result is used by writeNginxBlocklist to
  write the actual blocklist file.
  """
  blocked_ips = []
  for url in BLOCKLISTS:
    blocklist = getFile(url)
    blocked_ips.extend(parseBlocklist(blocklist))
  return sorted(list(set(blocked_ips)))
    
def parseBlocklist(blocklist):
  """
  Parses the received file object line by line, looking for CIDR IP ranges (both IPv4 and IPv6).
  """
  ips = [] # List holding the detected IP ranges
  logging.debug('Scanning for IP ranges in %s.' % blocklist.geturl())
  validator = CIDRValidator() # Setting up new validator for CIDR address ranges
  for line in blocklist: # Iterate through file object
    line = line.decode('utf8').rstrip('\n') # Convert from byte to utf8-encoded string
    ip = validator.validate(line)
    if ip: # If a match is found...
      logging.debug('Found IP range %s.' % ip)
      ips.append(ip) # ...add it to the list
    else:
      logging.debug('No IP range found in line: %s' % line)
  if not ips: # Give a warning if no IP range could be found in the entire file
    logging.warning('Could not extract any IPs from server response! URL: %s' % blocklist.geturl())
  return ips
  
def writeNginxBlocklist(ips):
  """
  Write a new blocklist file from an IP range list. Don't overwrite the old one, if the new list
  would be empty.
  """
  if ips: # Only regenerate the file of the IP range list is not empty
    logging.debug('Opening %s/%s for writing.' % (NGINX_CONF_DIR, NGINX_DROP_CONF))
    try:
      f = open('%s/%s' % (NGINX_CONF_DIR, NGINX_DROP_CONF), 'w') #  open blocklist file for writing
    # Catch errors while opening file
    except IOError as e: 
      logging.critical('Failed to open %s/%s: %s' % (NGINX_CONF_DIR, NGINX_DROP_CONF, e))
    except:
      logging.critical('Unknown error while tyring to open %s/%s' % (NGINX_CONF_DIR, NGINX_DROP_CONF))
    for ip in ips: # Iterate through IP range list
      logging.debug('Adding IP range: %s' % ip)
      f.write('deny %s;\n' % ip) # write rule to file
    f.close()
    logging.info('Writing %d rules to %s/%s was successful!' % (len(ips), NGINX_CONF_DIR, NGINX_DROP_CONF))
  else:
    # Throw a warning if no list was generated
    logging.warning('Generated blocklist was empty! The old list in %s/%s was _not_ overwritten!' % (NGINX_CONF_DIR, 
                                                                                                     NGINX_DROP_CONF))
  
def reloadNginxConfig():
  """
  Reload nginx after writing the new blocklist file.
  """
  try:
    logging.debug('Reloading nginx config.')
    check_call([NGINX_EXEC, '-s', 'reload']) # Reload nginx, throw exception if error is returned
  except CalledProcessError as e:
    logging.critical('Failed to reload nginx config: %s' % e)
  except OSError as e:
    logging.critical('Failed to execute nginx: %s' % e)
  except:
    logging.critical('Unknown error occurred while reloading nginx config!')
  else:
    logging.info('Reloaded nginx config successfully!')

def main():
  setupLogHandler() # Set up logging to stdout and logfile 
  logging.info('Generating new IP blocklist for nginx.')   
  writeNginxBlocklist(collectBlockedIps()) # Generate a list of IP ranges to be blocked and write them to a
                                           # rule file for nginx
  reloadNginxConfig() # Reload nginx in order to apply the blocking rules
  logging.info('Generating IP blocklist for nginx finished!')
  
if __name__ == "__main__":
  main()