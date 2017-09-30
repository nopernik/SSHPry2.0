#!/usr/bin/python

import termios, fcntl
import sys

command = sys.argv[1]
tty = sys.argv[2]

with open(tty) as f:
   for c in command.decode('string_escape'):
      fcntl.ioctl(f,termios.TIOCSTI,c)


