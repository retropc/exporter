def si(x, u=" kMGTPE"):
  if x == 0: return ""
  m = 1
  for cu in u:
    nm = m * 1024
    if x > nm * 2:
      m = nm
    else:
      break

  return "%d%sB" % (x // m, "" if m == 1 else cu)


