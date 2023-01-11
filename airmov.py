#!/usr/bin/env python3
import socket
import sys
import os


AP_FMT = "%s %7d %s"

class AP:
  def __init__(self, BSSID, Beacons, ESSID):
    self.BSSID = BSSID
    self.Beacons = Beacons
    self.ESSID = ESSID
  def inc(self):
    self.Beacons += 1
    return

def screen(CH, ap):
  os.system("clear")
  print("BSSID             Beacons ESSID [CH : %2d] airmov 1.0 " % CH)
  print("")
  for i in ap.values():
    print(AP_FMT % (i.BSSID, i.Beacons, i.ESSID))

def airmon(interface, console=False, loop=60):
  soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
  soc.bind((interface, 0x0003))
  ap = {}
  i = 0
  ch = 1
  while type(loop) == type(None) or i < loop:
    i += 1

    ch = ((ch + 1) % 13) + 1
    os.system("sudo iwconfig %s channel %d" % (interface, ch))

    try:
      packet = soc.recvfrom(4096)[0]
    except:
      continue

    if len(packet) < 0x30: continue

    if packet[0x18] != 0x80: continue

    BSSID = packet[0x27:0x27 + 6]
    BSSID = list(map(int, BSSID))

    tmp = BSSID.pop(0)
    BSSID.append(tmp)
    BSSID = tuple(BSSID)

    BSSID = "%02X:%02X:%02X:%02X:%02X:%02X" % BSSID

    if BSSID in ap:
      ap[BSSID].inc()
      if console: screen(ch, ap)
      continue

    ESSID_length = packet[0x3d]
    ESSID = packet[0x3e:0x3e + ESSID_length + 1]
    
    if ESSID[0] < ord(" "): continue
  
    ESSID = ESSID.decode()

    ap[BSSID] = AP(BSSID, 1, ESSID)

    if console: screen(ch, ap)
  return ap

if __name__ == "__main__":
  airmon(sys.argv[1], console=True, loop=None)
