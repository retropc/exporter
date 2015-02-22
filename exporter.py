#!/usr/bin/python

import subprocess
import os
import signal
import socket
import hmac
import struct
import time
import hashlib
import traceback
import select
import sys
import prctl
from config import KEY, TARGET

HEADER = "      NAME  STATE   CPU(sec) CPU(%)     MEM(k) MEM(%)  MAXMEM(k) MAXMEM(%) VCPUS NETS NETTX(k) NETRX(k) VBDS   VBD_OO   VBD_RD   VBD_WR  VBD_RSECT  VBD_WSECT SSID"
#HEADER = "      NAME  STATE   CPU(sec) CPU(%)     MEM(k) MEM(%)  MAXMEM(k) MAXMEM(%) VCPUS NETS NETTX(k) NETRX(k) VBDS   VBD_OO   VBD_RD   VBD_WR SSID\n"

DEVNULL = os.open(os.devnull, os.O_RDWR)

def run(sender, signer):
  buf = ""

  p = subprocess.Popen(["/usr/bin/sudo", "/usr/sbin/xentop", "-nxvbfd", "60"], shell=False, stdin=DEVNULL, stdout=subprocess.PIPE, stderr=DEVNULL, close_fds=True)
  try:
    fd = p.stdout.fileno()

    existing_interfaces = []
    while True:
      r, w, x = select.select([fd], [], [])

      if r:
        ret = os.read(fd, 65535)
        if not ret:
          print >>sys.stderr, "process terminated :("
          break

        buf+=ret

        pos = buf.find(HEADER)
        if pos == -1:
          continue

        t2 = time.time()
        segment = buf[:pos-1]
        buf = buf[pos+len(HEADER):]
        if segment == "" or pos == 0: # first iteration
          t = t2
          continue

        interfaces = get_interfaces()
        if interfaces != existing_interfaces:
          existing_interfaces = interfaces
          domains = get_domains()

        sender.send(signer.sign(t, segment, interfaces, domains))

        t = t2
  finally:
    p.stdout.close()

    p.kill()
    p.wait()

def get_domains():
  print >>sys.stderr, "domains changed, running xm list..."
  p = subprocess.Popen(["/usr/bin/sudo", "/usr/sbin/xm", "list"], shell=False, stdin=DEVNULL, stdout=subprocess.PIPE, stderr=DEVNULL, close_fds=True)
  try:
    fd = p.stdout.fileno()
    buf = []
    while True:
      ret = os.read(fd, 65535)
      if not ret:
        break
      buf.append(ret)
    return "\n".join(buf).strip()
  finally:
    p.stdout.close()
    if p.wait() != 0:
      print >>sys.stderr, "bad return code from xm list"
      return ""

def get_interfaces():
  f = open("/proc/net/dev", "rb")
  try:
    l = iter(f)
    try:
      l.next()
      l.next()
      ifs = []
      for l in f:
        t = l.split(":", 2)[0].strip()
        if t.startswith("vif"):
          ifs.append(t[3:])
      return "\n".join(ifs).strip()
    except StopIteration:
      return []
  finally:
    f.close()

class PacketGenerator(object):
  max_counter = 2**32-1
  def __init__(self):
    self.h = hmac.HMAC(key=KEY, digestmod=hashlib.sha1)
    self.counter = 0
    self.ur = open("/dev/urandom", "rb")

  def sign(self, t, data, interfaces, domains):
    rabuf = self.ur.read(4)
    if len(rabuf) != 4:
      raise Exception("urandom dead")

    hdata = "%s%s%s%s%s" % (rabuf, struct.pack("!LLHH", self.counter, int(t), len(interfaces), len(domains)), interfaces, domains, data)

    self.counter+=1
    if self.counter > self.max_counter:
      self.counter = 0

    h2 = self.h.copy()
    h2.update(hdata)
    packet = "%s%s" % (h2.digest(), hdata)
    return struct.pack("i", len(packet)) + packet

class UDPSender(object):
  def __init__(self):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(TARGET)

  def send(self, s):
    try:
      self.send(s)
    except socket.error:
      traceback.print_exc()

class TCPSender(object):
  def __init__(self):
    self.s = None

  def connect(self):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
      s.connect(TARGET)
      self.s = s
    except:
      s.close()
      raise

  def send(self, s):
    try:
      if self.s is None:
        self.connect()

      self.s.send(s)
    except socket.error:
      self.s = None
      traceback.print_exc()

def main():
  prctl.deathsig(signal.SIGTERM)
  signal.signal(signal.SIGPIPE, signal.SIG_IGN)

  sender = TCPSender()
  signer = PacketGenerator()

  while True:
    started = time.time()
    try:
      run(sender, signer)
    except:
      traceback.print_exc()

    delta = time.time() - started
    if delta < 10:
      print >>sys.stderr, "uh oh, crashing lots... sleeping"
      time.sleep(10 - delta)

if __name__ == "__main__":
  main()

