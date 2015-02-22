import re

import hmac
import hashlib
import struct
import time
import collections

class ParseException(Exception): pass
class BadStateException(Exception): pass

#     boxbox --b---      11586    0.2     131072    1.6     131072       1.6     1    2 90817371  2945794    2     2712  3280355  1382648 1 1 2149627072

HEADER = "      NAME  STATE   CPU(sec) CPU(%)     MEM(k) MEM(%)  MAXMEM(k) MAXMEM(%) VCPUS NETS NETTX(k) NETRX(k) VBDS   VBD_OO   VBD_RD   VBD_WR  VBD_RSECT  VBD_WSECT SSID"
#HEADER = "      NAME  STATE   CPU(sec) CPU(%)     MEM(k) MEM(%)  MAXMEM(k) MAXMEM(%) VCPUS NETS NETTX(k) NETRX(k) VBDS   VBD_OO   VBD_RD   VBD_WR SSID"
DOMAIN_RE = re.compile(r"\A *([a-zA-Z\-0-9]+) +([rbpscd-]{6}) +(\d+) +([\d\.]+) +(\d+) +([\d\.]+) +(\d+|no limit) +([\d\.]+|n/a) +(\d+) +(\d+) +(\d+) +(\d+) +(\d+) +(\d+) +(\d+) +(\d+) +(\d+) +(\d+) +(\d+)\Z")
#VCPUs(sec):   0:      11586s   1:    1s
VCPU_RE = re.compile(r"\AVCPUs\(sec\):(( +(\d+): +(\d+)s)+)\Z")
VCPU_INDIV_RE = re.compile(r" +(\d+): +(\d+)s")
#Net0 RX: 2790485492bytes 35012719pkts        0err     2670drop  TX: 92994945727bytes 20765486pkts        0err        0drop
NET_RE = re.compile(r"\ANet(\d+) RX: +(\d+)bytes +(\d+)pkts +(\d+)err +(\d+)drop +TX: +(\d+)bytes +(\d+)pkts +(\d+)err +(\d+)drop\Z")
#VBD BlkBack 2049 [ 8: 1]  OO:     2709   RD:  3256438   WR:  1381742  RSECT: 1   WR: 1
VBD_RE = re.compile(r"\AVBD BlkBack +(\d+) +\[ *(\d+|ca): *(\d+) *\] +OO: +(\d+) +RD: +(\d+) +WR: +(\d+) +RSECT: +(\d+) +WSECT: +(\d+)\Z")
DOMAIN_STATES = {
  "r": "running",
  "b": "blocked",
  "p": "paused",
  "s": "shutdown",
  "c": "crashed",
  "d": "dying",
}

DOMAIN_HEADER = "Name                                        ID   Mem VCPUs      State   Time(s)"

STATE_DOMAIN, STATE_VCPU, STATE_NET, STATE_VBD = range(4)

VCPU = collections.namedtuple("VCPU", ["time"])
VBD = collections.namedtuple("VBD", ["oo", "rd", "wr", "rsect", "wsect", "minor", "major"])
VIFStats = collections.namedtuple("VIFStats", ["bytes", "packets", "errors", "drops"])
VIF = collections.namedtuple("VIF", ["tx", "rx"])
Domain = collections.namedtuple("Domain", ["vcpus", "vbds", "vifs", "state", "cpu_percentage", "mem_kb", "mem_percentage", "maxmem_kb", "maxmem_percentage", "ssid", "id"])

SECTOR_MASK = int("111111111111111111111111111111", 2)

def from_locals(l, *items):
  def fn():
    for x in items:
      yield x, l[x]
  return dict(fn())

def coerce(type, value):
  try:
    return type(value)
  except ValueError:
    return -1

EXPANDERS = {
  "_": lambda x: None,
  "d": lambda x: int(x),
  "f": lambda x: float(x),
  "s": lambda x: x,
  "S": lambda x: [DOMAIN_STATES[y] for y in x.replace("-", "")],
  "D": lambda x: coerce(int, x),
  "F": lambda x: coerce(float, x),
  "x": lambda x: int(x, 16),
}

def expand(m, format):
  if not isinstance(m, tuple):
    m = m.groups()

  result = [None] * len(m)
  for i, (x, y) in enumerate(zip(format, m)):
    result[i] = EXPANDERS[x](y)
  return result

EMPTY = (-1, [])
def parse_xentop(lines, vif_map={}):
  state = STATE_DOMAIN
  data = {}
  for line in lines[1:]:
    try:
      if state == STATE_DOMAIN:
        m = DOMAIN_RE.match(line)
        if not m:
          raise ParseException, "Header or domain expected."

#        domain_name, domain_state, cpu_sec, cpu_percentage, mem_kb, mem_percentage, maxmem_kb, maxmem_percentage, vcpus_remaining, nets_remaining, net_tx_kb, net_rx_kb, vbds_remaining, vbd_oo, vbd_rd, vbd_wr, vbd_rsect, vbd_wsect, ssid = expand(m, "sSdfdfDFddddddddd")
        domain_name, domain_state, _, cpu_percentage, mem_kb, mem_percentage, maxmem_kb, maxmem_percentage, vcpus_remaining, nets_remaining, _, _, vbds_remaining, _, _, _, _, _, ssid = expand(m, "sS_fdfDFdd__d___d")

        nets = {}
        vcpus = {}
        vbds = {}

        domain_id, domain_vifs = vif_map.get(domain_name, EMPTY)
        data[domain_name] = domain = Domain(state=domain_state, vcpus=vcpus, vifs=nets, vbds=vbds, cpu_percentage=cpu_percentage, mem_kb=mem_kb, mem_percentage=mem_percentage, maxmem_kb=maxmem_kb, maxmem_percentage=maxmem_percentage, ssid=ssid, id=domain_id)

        # sadly we don't have nonlocal
        if vcpus_remaining == 0:
          if nets_remaining == 0:
            if vbds_remaining == 0:
              state = STATE_DOMAIN
            else:
              state = STATE_VBD
          else:
            state = STATE_NET
        else:
          state = STATE_VCPU

      elif state == STATE_VCPU:
        m = VCPU_RE.match(line)
        if not m:
          raise ParseException, "VCPU expected."

        all_vcpus = m.groups(1)[0]
        for m in VCPU_INDIV_RE.findall(all_vcpus):
          vcpu_number, vcpu_time = expand(m, "dd")
          vcpus[vcpu_number] = VCPU(time=vcpu_time)

#        vcpus_remaining = vcpus_remaining - 1
#        if vcpus_remaining == 0:
        if nets_remaining == 0:
          if vbds_remaining == 0:
            state = STATE_DOMAIN
          else:
            state = STATE_VBD
        else:
          state = STATE_NET
      elif state == STATE_NET:
        m = NET_RE.match(line)
        if not m:
          raise ParseException, "NET expected."

        net_position, net_rx_bytes, net_rx_packets, net_rx_errors, net_rx_drops, net_tx_bytes, net_tx_packets, net_tx_errors, net_tx_drops = expand(m, "ddddddddd")
        if domain_vifs and net_position < len(domain_vifs):
          nets[domain_vifs[net_position]] = VIF(
            rx=VIFStats(bytes=net_rx_bytes, packets=net_rx_packets, errors=net_rx_errors, drops=net_rx_drops),
            tx=VIFStats(bytes=net_tx_bytes, packets=net_tx_packets, errors=net_tx_errors, drops=net_tx_drops)
          )

        nets_remaining = nets_remaining - 1
        if nets_remaining == 0:
          if vbds_remaining == 0:
            state = STATE_DOMAIN
          else:
            state = STATE_VBD
      elif state == STATE_VBD:
        m = VBD_RE.match(line)
        if not m:
          raise ParseException, "VBD expected."

        vbd_number, vbd_major, vbd_minor, vbd_oo, vbd_rd, vbd_wr, vbd_rsect, vbd_wsect = expand(m, "dxxddddd")
        vbds[vbd_number] = VBD(oo=vbd_oo, rd=vbd_rd, wr=vbd_wr, major=vbd_major, minor=vbd_minor, rsect=vbd_rsect & SECTOR_MASK, wsect=vbd_wsect & SECTOR_MASK)

        vbds_remaining = vbds_remaining - 1
        if vbds_remaining == 0:
          state = STATE_DOMAIN
      else:
        raise BadStateException, state

    except ParseException, e:
      raise ParseException, "%s (line: %s)" % (e.message, repr(line))

  return data

def parse_domains(lines):
  if lines[0] != DOMAIN_HEADER:
    raise ParseException("First line is not header: %r" % lines[0])

  d = {}
  for line in lines[1:]:
    tokens = line.split(None, 2)
    name, id_ = tokens[0], tokens[1]
    d[id_] = name
  return d

__all__ = "parse_xentop", "parse_domains"

if __name__ == "__main__":
  import pprint

  data = [x for x in open("exampledata", "r").read().split("\n") if x]

  for i, x in enumerate(data):
    if x == HEADER:
      domains, full_data = data[:i], data[i:]
      break

  print domains, full_data
  vifmap = parse_domains(domains)
  pprint.pprint(parse_xentop(full_data, vifmap))
