import socket
from config import PREFIX

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(("127.0.0.1", 2003))
def send_data(t, data):
  metrics = []
  for machine, data in data.items():
    for key, value in data.items():
      metrics.append("%s.%s.%s %d %d" % (PREFIX, machine, key, value, t))
  try:
    s.send("\n".join(metrics))
  except socket.error:
    pass

