import ctypes

PR_SET_PDEATHSIG = 1

libc = ctypes.CDLL("libc.so.6")
prctl = libc.prctl

def deathsig(signum):
  if libc.prctl(PR_SET_PDEATHSIG, signum) != 0:
    raise Exception()

