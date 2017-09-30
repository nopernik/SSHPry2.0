#!/usr/bin/python

# Getchar.py echoes every single keypress
#
# Author: Alexander Korznikov
# Twitter: @nopernik
# git: https://github.com/nopernik
# my blog: http://korznikov.com
# my challenges: http://sudo.co.il

import termios, fcntl, sys, os, re

class z:
   working = True
   pass

def GetKeystrokes(b):
   fd = sys.stdin.fileno()

   oldterm = termios.tcgetattr(fd)
   newattr = termios.tcgetattr(fd)
   newattr[3] = newattr[3] & ~termios.ICANON & ~termios.ECHO
   termios.tcsetattr(fd, termios.TCSANOW, newattr)

   oldflags = fcntl.fcntl(fd, fcntl.F_GETFL)
   fcntl.fcntl(fd, fcntl.F_SETFL, oldflags | os.O_NONBLOCK)

   try:
      while z.working:
         try:
            c = sys.stdin.read(1)
            print repr(c)
         except IOError: pass
   finally:
      termios.tcsetattr(fd, termios.TCSAFLUSH, oldterm)
      fcntl.fcntl(fd, fcntl.F_SETFL, oldflags)

GetKeystrokes(0)
