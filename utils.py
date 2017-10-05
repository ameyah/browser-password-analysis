def is_process_running(process):
  import re
  import subprocess

  running = False
  processlist = subprocess.Popen(["ps", "ax"],stdout=subprocess.PIPE)
  for a in processlist.stdout:
      if re.search(process, a):
          running = True

  return running