#!/usr/bin/env python3
#
# This script uses ssh keys to login to a remote device. To prepare for this,
# we need to do :
#
# 1. Generate a new ssh key pair
#      % ssh-keygen -t rsa -C <user> -f <key_prefix>
#
# 2. Configure the AP to accept scp connections
#      my-ap1(config)#ip scp server enable
#
# 3. Upload the public key for <user>.
#      % scp -p <pub_key> admin@my-ap1:
#
# 4. Configure the AP to use this key for <user>.
#      % my-ap1(config)#ip ssh peer <user> public-key rsa flash:<pub_key>
#
# 5. Verify that we can ssh into the AP using this key
#      % ssh -i <pri_key> <user>@my-ap1
#
# This script is mostly a connection manager. Its job is to maintain the ssh
# connection to the device we're monitoring. Its role at this point is to
# periodically spawn helpers (eg, every minute, etc). Each helper sends us 
# one or more command it wants to execute (eg, "show xyz"). This script then
# delivers that command to the device, collects the response and sends it back
# to that helper. The helper may then send further commands for us to execute
# (eg, "show xxx detail") or it could return us metrics that we will expose
# for prometheus scrapes.
#
# The communication between this script and its helpers is via JSON. The
# following message formats are supported :
#
#  a) helper requests us to execute a command:
#       { "command" : "<cmd...>" }
#
#  b) send reply back to helper (newlines are literally the string '\n'):
#       { "response" : "<line1...>\n<line2...>\n..." }
#
#  c) helper sends us metrics to be exposed:
#       { "metrics" : {
#                       "<identifier>{<keyX>=\"<metaX>\",...}" : <num_value>,
#                       ...
#                     } }
#
# When this script spawns a helper, it interacts with the helper by writing
# to its stdin, reading from its stdout, until the helper closes both its
# stdin and stdout (ie, exits). Metrics supplied to us by the helper(s) are
# stored locally and are exposed via a web server which runs in a dedicated
# thread.

import os
import sys
import json
import time
import select
import signal
import threading
import subprocess
import http.server

cfg_user = "ap_exporter"
cfg_host = "fs-ap1"
cfg_sshkey = "ap_exporter.key"
cfg_prompt = "fs-ap1#"
cfg_poll_secs = 60      # how often we call helpers to update metrics
cfg_stale_secs = 90     # metrics older than this will not be exposed

rt_debug = 0            # debug output, 0=off 1=on, SIGUSR1=off SIGUSR2=on
rt_metrics = {}         # metrics we received from helpers
rt_running = 1          # our master switch
rt_connected = 0        # whether we're ssh'ed into the device we're monitoring
rt_ssh = None           # handle to the "ssh" child process

# -----------------------------------------------------------------------------

class c_handler(http.server.BaseHTTPRequestHandler):

  # This function is called whenever a client performs an HTTP GET. Make sure
  # the caller is requesting "/metrics" and then dump "rt_metrics".

  def do_GET(self):
    print("NOTICE: do_GET() %s" % self.path)
    if (self.path != "/metrics"):
      self.send_response(404)
      self.end_headers()
      return

    self.send_response(200)
    self.send_header("Content-type", "text/plain")
    self.end_headers()

    buf = ""
    now = time.time()
    for k in rt_metrics.keys():
      if (now - rt_metrics[k]["ts"] < cfg_stale_secs):
        if isinstance(rt_metrics[k]["value"], int):
          buf += "%s %d\n" % (k, rt_metrics[k]["value"])
        if isinstance(rt_metrics[k]["value"], float):
          buf += "%s %f\n" % (k, rt_metrics[k]["value"])

    self.wfile.write(str.encode(buf))

  # By default, the http.server emits each HTTP request, eg:
  #   127.0.0.1 - - [03/Oct/2021 14:42:28] "GET / HTTP/1.1" 200 -
  # To suppress this, we override this function with empty code.

  def log_message(self, format, *args):
    return

def f_httpdThread(port):
  try:
    webserver = http.server.HTTPServer(('0.0.0.0', port), c_handler)
    webserver.serve_forever()
  except:
    e = sys.exc_info()
    print("WARNING: Web server not running - %s" % e[1])

# -----------------------------------------------------------------------------

# Fire off ssh to login to "cfg_host" as "cfg_user" using "cfg_sshkey". Note
# that ssh expects its stdin to be a terminal so we need to call os.openpty()
# to create a pair of master/slave file descriptors (ie, writing to the master
# delivers data to ssh's stdin). On success, we return the file descriptors
# for stdin, stdout and stderr, or -1/-1/-1 if something went wrong.

def f_connect():
  pty_m, pty_s = os.openpty()
  args = [ "ssh", "-x",
           "-o", "StrictHostKeyChecking=no",
           "-o", "ServerAliveInterval=20",
           "-o", "BatchMode=no",
           "-i", cfg_sshkey,
           "%s@%s" % (cfg_user, cfg_host) ]
  try:
    ssh = subprocess.Popen(args,
                           shell=False,
                           stdin=pty_s,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
  except:
    e = sys.exc_info()
    print ("WARNING: cannot execute '%s' - %s" % (args[0], e[1]))
    return (-1, -1, -1)

  return (pty_m, ssh)

# This function is supplied the stdout and stderr of an "ssh" process. Our job
# is to collect any data from ssh's stdout, until "cfg_prompt" is encountered.
# At this point, we return all the data we've accumulated. If we received data
# on stderr, that means something is wrong and we return None.

def f_wait_for_prompt(stdout_fd, stderr_fd):

  buf = ""
  while (1):
    timeout = 2.0
    rlist = [ stdout_fd, stderr_fd ]
    try:
      rfds, wfds, efds = select.select(rlist, [], [], timeout)
    except:
      e = sys.exc_info()
      print("WARNING: select() failed - %s" % e[1])
      return None

    if stdout_fd in rfds:
      s = str(os.read(stdout_fd, 4096), "utf-8")
      if (len(s) < 1):
        print("WARNING: cannot read stdout.")
        return None                             # opsie ! connection closed ?
      buf = buf + s.replace("\r", "")

    if (buf.endswith(cfg_prompt)):
      endpoint = len(cfg_prompt)
      buf = buf[:-endpoint].rstrip("\n")
      return(buf)

    if stderr_fd in rfds:
      s = str(os.read(stderr_fd, 4096), "utf-8")
      if (len(s) < 1):
        print("WARNING: cannot read stderr.")
        return None                             # opsie ! connection closed ?
      print("WARNING: %s" % s)
      return None

def f_signal_handler(sig, frame):
  global rt_debug
  global rt_running

  if (sig == signal.SIGINT) or (sig == signal.SIGTERM):
    rt_running = 0 ;
    print("NOTICE: shutting down.")

  if (sig == signal.SIGUSR1):
    print("NOTICE: debug is off.")
    rt_debug = 0

  if (sig == signal.SIGUSR2):
    print("NOTICE: debug is on.")
    rt_debug = 1

# -----------------------------------------------------------------------------

# parse commandline, place our helpers into an array.

if (len(sys.argv) < 3):
  print("Usage: %s <webserver port> <helper1> [<helperN> ...]" % sys.argv[0])
  sys.exit(1)

# set debug level if DEBUG is specified

if os.getenv("DEBUG") is not None:
  rt_debug = int(os.getenv("DEBUG"))

port = int(sys.argv[1])
t_ws = threading.Thread(target=f_httpdThread, args=(port,))
t_ws.daemon = True
t_ws.start()

helper = []
for i in range(2, len(sys.argv)):
  helper.append(sys.argv[i])

# setup signal handling

signal.signal(signal.SIGINT, f_signal_handler)
signal.signal(signal.SIGTERM, f_signal_handler)
signal.signal(signal.SIGUSR1, f_signal_handler)
signal.signal(signal.SIGUSR2, f_signal_handler)

# program's main loop

last_run = time.time()
while (rt_running):

  # connect to the device we're monitoring, if we need to.

  if (rt_connected == 0):
    print("NOTICE: Connecting to %s." % cfg_host)
    stdin_fd, rt_ssh = f_connect()
    stdout_fd = rt_ssh.stdout.fileno()
    stderr_fd = rt_ssh.stderr.fileno()

    if (f_wait_for_prompt (stdout_fd, stderr_fd) is not None):
      print("NOTICE: Logged in as %s." % cfg_user)
      rt_connected = 1

  # run through each helper

  for i in range(0, len(helper)):
    try:
      p = subprocess.Popen ([ helper[i] ], shell=False,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    except:
      e = sys.exc_info()
      print("FATAL! Cannot run %s - %s" % (helper[i], e[1]))
      sys.exit(1)

    # keep reading commands (or metrics) from helper until it disconnects.

    while(1):
      buf = str(p.stdout.readline(), "utf-8")
      if (len(buf) < 1):
        break
      req = {}
      try:
        req = json.loads(buf)
      except:
        e = sys.exc_info()
        print("WARNING: Bad JSON from '%s' - %s" % (helper[i], e[1]))

      if ("command" in req):    # helper sent us a "command"

        if (rt_debug):
          print("DEBUG: command(%s)" % req["command"])
        if (req["command"].endswith("\n") == False):
          req["command"] += "\n"
        os.write(stdin_fd, str.encode(req["command"]))
        reply = {}
        reply["command"] = req["command"].rstrip("\n")
        reply["response"] = f_wait_for_prompt(stdout_fd, stderr_fd)
        if (reply["response"] == None):
          rt_connected = 0
          break # lost connection to device, we can't continue with helper

        if reply["response"].startswith(req["command"]):
          offset = len(req["command"])          # chop off echo'ed command
          reply["response"] = reply["response"][offset:]

        if (rt_debug):
          print("DEBUG: response: %s" % json.dumps(reply))
        p.stdin.write(str.encode(json.dumps(reply) + "\n"))
        p.stdin.flush()

      elif ("metrics" in req):  # helper sent us metrics

        if (rt_debug):
          print("DEBUG: received %d metrics : %s" % \
                (len(req["metrics"]), req["metrics"]))
        now = time.time()
        for k in req["metrics"].keys():
          if k in rt_metrics:           # update hash entry in "rt_metrics"
            rt_metrics[k]["ts"] = now
            rt_metrics[k]["value"] = req["metrics"][k]
          else:                         # create hash entry in "rt_metrics"
            x = {}
            x["ts"] = now
            x["value"] = req["metrics"][k]
            rt_metrics[k] = x
        break

      else:
        print("WARNING: No 'command' or 'metrics' from '%s', aborting." % \
              helper[i])
        break

    p.stdin.close()
    p.stdout.close()
    p.wait()
    if (rt_debug):
      print("DEBUG: helper '%s' exited %d." % (helper[i], p.returncode))

  # figure out how long we get to sleep

  last_run = last_run + cfg_poll_secs
  nap_duration = last_run - time.time()
  if (nap_duration > 0):
    print("NOTICE: sleeping for %d secs." % nap_duration)
    while (time.time() < last_run) and (rt_running):
      time.sleep(1)

if (rt_connected):
  os.close(stdin_fd)
  os.close(stdout_fd)
  os.close(stderr_fd)
  rt_ssh.terminate()

print("NOTICE: program terminated.")
sys.exit(0)

