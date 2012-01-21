# Python script for generating nginx IP blacklists

## Introduction
   
   This script will help you to prevent spam network IPs from
   accessing your nginx webserver. This is done by using services like the [Spamhaus Don't Route or Peer list (DROP)](www.spamhaus.org/drop/).
   The script is written in a way that it can be easily extended to make use of additional services that use a similar syntax to Spamhaus.
   

## Installation

   1. Clone the git repository from github:
   
      `git clone https://github.com/Athemis/gen_nginx_bl.git`
      
   2. Open `gen_nginx_bl.py` with a text editor of your choice and alter the variables on top to meet your system.
      Especially take care of `NGINX_CONF_DIR` which must point to the directory containing your `nginx.conf` and `LOG_FILE` which must point to an existing path. Make sure that your nginx executable is in your PATH or alternatively point `NGINX_CMD` to the full path of the nginx executable.
      
   3. Add the following line to your `nginx.conf` usually found under `/etc/nginx`:
   
      `include blocklist.conf`
      
      If you changed `NGINX_DROP_CONF` use its new value instead of `blocklist.conf`
      
   4. Execute `./gen_nginx_bl.py` as root and check the console output for error messages.
   
   5. Check the generated blacklist file found under `NGINX_CONF_DIR/NGINX_DROP_CONF`. It should contain entries in the form of
   
      `deny 103.10.188.0/22;`
      
   6. Consider adding the script to your cron jobs.
   

## Adding a cron job
  
   To run the script once a day, copy or symlink it to `/etc/cron.daily`:
   
   `cp gen_nginx_bl.py /etc/cron.daily`
      
   or
      
   `ln -s gen_nginx_bl.py /etc/cron.daily`
   
   For further information regarding cron, consult your distro's documentation.
