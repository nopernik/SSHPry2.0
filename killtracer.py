#!/usr/bin/python

# Find and stop tracing.
#
# Author: Alexander Korznikov
# Twitter: @nopernik
# Developed under GNU General Public License v 3.0

import os,psutil

ppid = psutil.Process(os.getppid()).ppid()
tracer = [i.split() for i in open('/proc/%s/status' % ppid).read().split('\n') if 'TracerPid:' in i][0]
if int(tracer[1]):
   print('[+] Tracing found! PID: %s' % tracer[1])
   os.kill(int(tracer[1]), 9)
   print('[+] Now it is safe to change password')
   os.system('passwd')
