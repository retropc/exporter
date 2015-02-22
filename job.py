#!/usr/bin/env python
import time
import fast_sink
import sys
from util import si

DSES = "rx.0", "tx.0", None, None, "rd", "wr", "cpu"
#DSES = "rx.0", "tx.0", "rx.1", "tx.1", "rd", "wr", "cpu"
COL_ORDER = 1, 2, 3, 4, 5, 6, 0
UNITS = si, si, si, si, lambda x: si(x * 512), lambda x: si(x * 512), lambda x: "%ds" % x

def aggregate(f, fn):
  keyfn = lambda x: fn(x[0])
  results = []
  for machine, itt in ((y.machine, iter(y)) for y in f):
    buckets = {}
    for x in itt:
      buckets.setdefault(fn(x[0]), []).append((x[0], x[1:]))

    sd = {}
    for k, v in buckets.iteritems():
      summed = [0] * len(DSES)
      min = last = v[0][1]
      for ts, x in v[1:]:
        delta = subtract(x, last)
        last = x
        if any(x < 0 for x in delta):
          continue
        summed = add(summed, delta)
      
      sd[k] = summed
    results.append((machine, sd))

  return dict(results)

def add(x, y):
  return [a + b for a, b in zip(x, y)]
def subtract(x, y):
  return [a - b for a, b in zip(x, y)]

def render_table(f, secondary_key, format_len=8):
  l = []
  def p(*args):
    l.append(" ".join(args))

  if len(COL_ORDER) != len(DSES) or len(UNITS) != len(DSES):
    raise Exception("All constants must be the same length!")

  format = "%%%ds" % format_len
  dashes, spaces = "-" * format_len, " " * format_len
  header =  (" %s   %s " % (spaces, "    " if secondary_key else "")) + " | ".join(format % x for _, x in sorted(zip(COL_ORDER, DSES)) if x)
  divider = ("-%s-|-%s-" % (dashes, "----" if secondary_key else "")) + ("-|-".join(dashes for x in list(DSES) if x))

  p(header)

  def render_line(v):
    return " | ".join(x for _, x in sorted((order, format % unit(v)) for unit, v, order, z in zip(UNITS, v, COL_ORDER, DSES) if z))

  for j, (machine, d) in enumerate(sorted(f.iteritems(), key=lambda x: x[0])):
    short_machine = machine[:format_len]
    if secondary_key:
      p(divider)
      for i, (hour, v) in enumerate(sorted(d.iteritems())):
        p((" " + format + " | %2s |") % (short_machine if i == 0 else "", hour), render_line(v))
    else:
      if j % 5 == 0:
        p(divider)

      if len(d) != 1:
        raise Exception()

      p((" " + format + " | ") % machine[:format_len], render_line(d[0]))

  return "\n".join(l)

def hour(x, lt=time.localtime):
  return lt(x).tm_hour
  
def day(x):
  return 0
  
def main(offset, warning):
  f = fast_sink.FastSink()
  f.begin(time.time() - offset)

  by_hour = aggregate(f, hour)
  by_day = aggregate(f, day)

  if warning:
    large_users = {}
    LIMIT = 1024 * 1024 * warning
    for machine, v in by_day.items():
      rx, tx, _, _, _, _, _ = v.values()[0]
      if rx > LIMIT or tx > LIMIT:
        large_users[machine] = (rx, tx)

    if large_users:
      print "Used over %s:" % si(LIMIT) #, ", ".join(k for k in large_users.keys())
      print "\n".join("  - %s (rx: %s tx: %s)" % (k, si(v[0]), si(v[1])) for k, v in large_users.iteritems())
      return 1
  else:  
    print "\n".join("    " + x for x in render_table(by_day, False).split("\n"))
    print
    print render_table(by_hour, True)

  return 0

if __name__ == "__main__":
  args = sys.argv[1:]

  warning = False
  if args and args[0] == "-w":
    args.pop(0)
    warning = int(args.pop(0))

  sys.exit(main(int(args[0]) if args else 0, warning=warning))
