#!/usr/bin/python

import fast_sink as sink

import socket
import hmac
import hashlib
import xentop_parser
import re
import os
import pprint
import struct
import sys

from config import KEY, SOURCE, TARGET

def pick(vifs):
  return sorted(((vif.rx.bytes + vif.tx.bytes, vif) for vif in vifs.values()), reverse=True, key=lambda x: x[0])[0][1]

ALL_DOMAINS = {}
def handle_data(t, xentop_raw, interfaces_raw, domains_raw):
  domains = xentop_parser.parse_domains(domains_raw.split("\n"))
  ALL_DOMAINS.update(domains)

  interfaces = interfaces_raw.split("\n")

  # domains = {2: boxbox, ...}
  # interfaces = ["vif2.1", "vif2.0", ...]

  vifs = {}
  for vif in interfaces:
    id_, ifno = vif.split(".")
    id_ = id_.split("-")[0] # sometimes has -emu on the end
    name = ALL_DOMAINS.get(id_)
    if not name:
      continue
    vifs.setdefault(name, (int(id_), []))[1].append(int(ifno))

  # vifs = {boxbox: (id, [if#0, if#1]), ...}
  data = xentop_parser.parse_xentop(xentop_raw.split("\n"), vifs)

  v = dict((key,
  (
    ("rx.0", value.vifs[0].rx.bytes),
    ("tx.0", value.vifs[0].tx.bytes),
    ("rx.1", value.vifs[1].rx.bytes if 1 in value.vifs else 0),
    ("tx.1", value.vifs[1].tx.bytes if 1 in value.vifs else 0),
    ("rd", sum(x.rsect for x in value.vbds.values())),
    ("wr", sum(x.wsect for x in value.vbds.values())),
    ("cpu", sum(x.time for x in value.vcpus.values())),
  )) for key, value in data.items() if value.vifs)

  sink.send_data(t, v)

def main():
  h = hmac.HMAC(key=KEY, digestmod=hashlib.sha1)
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.bind(TARGET)

  while True:
    packet, source = s.recvfrom(65535)
    if not packet:
      continue
    if source[0] != SOURCE:
      continue

    hdata = packet[20:]
    h2 = h.copy()
    h2.update(hdata)
    if packet[:20] != h2.digest():
      continue

    jdata = hdata[8:]

    t, interfaces_len, domains_len = struct.unpack("!LHH", jdata[:8])
    interfaces_raw = jdata[8:8+interfaces_len]
    domains_raw = jdata[8+interfaces_len:8+interfaces_len+domains_len]
    xentop_raw = jdata[8+interfaces_len+domains_len:]
    try:
      handle_data(t, xentop_raw, interfaces_raw, domains_raw)
    except:
      with open("dumped-broken-data", "wb") as f:
        f.write(jdata)
     
      print >>sys.stderr, "Exception processing last message, contents: dumped to dumped-broken-data"
      raise

if __name__ == "__main__":
  main()
