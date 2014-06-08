import string
import time
import os
import struct
import errno

TARGET = "output"

SINK = None
ITEMS = 7

def send_data(t, data):
  global SINK
  if not SINK:
    SINK = FastSink(read_only=False)

  SINK.begin(t)
  try:
    for machine, data in data.items():
      SINK.add(machine, [x[1] for x in data])
  finally:
    SINK.close()

class FastSinkFile(object):
  FORMAT = struct.Struct("l" + ("q" * ITEMS))

  def __init__(self, machine, filename, read_only):
    self.machine = machine
    self._f = open(filename, ("r" if read_only else "a+") + "b")

  def read(self, count):
    self._f.read(count * self.FORMAT.size())

  def add(self, ts, values):
    if len(values) != ITEMS:
      raise Exception("Bad data len.")

    self._f.write(self.FORMAT.pack(ts, *values))
    self._f.flush()

  def first(self):
    try:
      return iter(self).next()
    except StopIteration:
      return None

  def last(self):
    self._f.seek(0, 2)
    pos = self._f.tell()
    if pos == 0:
      return None

    size = self.FORMAT.size
    if pos % self.FORMAT.size == 0:
      pos-=1

    last_record = (pos // self.FORMAT.size) * self.FORMAT.size
    for x in self.__iter__real(last_record):
      return x

  def __iter__(self):
    for x in self.__iter__real(0):
      yield x

  def __iter__real(self, start_at):
    self._f.seek(start_at)

    size = self.FORMAT.size
    if size > 16384:
      bufsize = size
    else:
      bufsize = (16384 // size) * size

    read, unpack = self._f.read, self.FORMAT.unpack

    buf = ""
    while True:
      while len(buf) < size:
        r = read(bufsize)
        if not r:
          return
        buf+=r

      l = len(buf)
      for pos in xrange(0, l, size):
        e = pos + size
        if e > l:
          buf = buf[pos:]
          break
        yield unpack(buf[pos:e])
      else:
        buf = ""

  @property
  def closed(self):
    return self._f is None

  def close(self):
    self._f.close()
    self._f = None

  def __repr__(self):
    return "<FastSink machine=%r>" % self.machine

class FastSink(object):
  PERMITTED = set(string.letters + string.digits + "_-.")

  def __init__(self, dir=TARGET, read_only=True):
    self.dir = dir
    self.read_only = read_only

    self._suffix = None
    self._cache = {}

  def __iter__(self):
    for x in os.listdir(self.dir):
      try:
        yield self.get(x)
      except IOError, e:
        if e.errno != errno.ENOENT:
          raise e

  def begin(self, t=None):
    if t is None:
      t = int(time.time())

    suffix = time.strftime("%Y/%m/%d", time.localtime(t))
    if suffix != self._suffix:
      self._suffix = suffix
      self.close()

    self._ts = t

  def get(self, machine):
    f = self._cache.get(machine)
    if f and not f.closed:
      return f

    if set(machine) - self.PERMITTED:
      raise Exception("Bad machine name: %s" % machine)

    path = "%s/%s.fs" % (machine, self._suffix)
    dir, _ = os.path.split(path)
    target_path = self.dir + "/" + dir
    if not os.path.exists(target_path):
      os.makedirs(target_path)
    self._cache[machine] = f = FastSinkFile(machine, "%s/%s" % (self.dir, path), self.read_only)

    return f

  def add(self, machine, values):
    self.get(machine).add(self._ts, values)

  def close(self):
    for f in self._cache.values():
      f.close()
    self._cache.clear()

  def __getitem__(self, value):
    return self.get(value)

  def __enter__(self):
    self.begin()

  def __exit__(self, *args):
    pass

if __name__ == "__main__":
  import sys
  import pprint
  import time

  f = FastSink()
  f.begin(time.time() - (1 * int(sys.argv[2])))

  m = list(dict((x.machine, x) for x in f)[sys.argv[1]])
  last = m.pop(0)

  for data in m:
    ts = data[0]

    t = [b - a for a, b in zip(last[1:], data[1:])]
    last = data
    print time.ctime(ts)[11:16], t[1:]
