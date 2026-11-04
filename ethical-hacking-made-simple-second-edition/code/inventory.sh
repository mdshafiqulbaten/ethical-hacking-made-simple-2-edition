     facts; it changes nothing.

      #!/usr/bin/env bash
      # inventory.sh - read-only facts about this Linux host, with a
      timestamp
      set -u
      echo "== Inventory $(date -u +%Y-%m-%dT%H:%M:%SZ) =="
      echo "host   : $(hostname)"
      echo "user   : $(id -un) (uid $(id -u))"
      echo "os     : $(. /etc/os-release && echo "$PRETTY_NAME")"
      echo "kernel : $(uname -r)"
      echo "disk / : $(df -h / | awk 'NR==2 {print $5 " used of "
      $2}')"
      echo "login shells:"
      awk -F: '$7 !~ /(nologin|false)$/ {print " " $1 " (uid " $3
      ")"}' /etc/passwd

      $ ./inventory.sh | tee inventory-$(date +%F).txt

     Real output (Ubuntu 24.04, trimmed; your values will differ):

      == Inventory 2026-10-29T02:03:39Z ==
      host    : ubuntu01
      user    : analyst (uid 30033)
      os      : Ubuntu 24.04.5 LTS
      kernel : 6.18.44-fc-v185
      disk / : 30% used of 252G
      login shells:
         root (uid 0)

     Read the result. Every value is quoted, the script collects facts with‐
     out changing anything, and tee shows the report while saving it. A
     reviewer can read the whole script in thirty seconds, which is the
     point.

         FROM SAFE CYBER RANGES TO PROFESSIONAL REPORTS

L A B 5.3 · C R E AT E A N D V E R I F Y A N E V I D E N C E M A N I F E S T

Machine: Kali · Time: 20 minutes · Evidence file: manifest.csv

A manifest records the SHA-256 hash of each evidence file. If a file
changes later, the hash changes, and you can prove it. Save as
hash_manifest.py :

 # hash_manifest.py - record or verify SHA-256 hashes for an evi‐
 dence folder
 # create: python3 hash_manifest.py evidence -o manifest.csv
 # verify: python3 hash_manifest.py evidence --verify
 manifest.csv
 import argparse, csv, hashlib, sys
 from pathlib import Path

 def sha256(path):
     h = hashlib.sha256()
     with open(path, "rb") as f:
         for chunk in iter(lambda: f.read(65536), b""):
             h.update(chunk)
     return h.hexdigest()

 def scan(folder):
     return {str(p.relative_to(folder)): sha256(p)
              for p in sorted(Path(folder).rglob("*")) if
 p.is_file()}

 def main():
     ap = argparse.ArgumentParser()
     ap.add_argument("folder")
     ap.add_argument("-o", "--output")
     ap.add_argument("--verify")
     args = ap.parse_args()
     now = scan(args.folder)
     if args.verify:
         with open(args.verify, newline="") as f:
             old = {row["file"]: row["sha256"] for row in
 csv.DictReader(f)}
         bad = 0
         for name in sorted(set(old) | set(now)):
             if name not in now:   status = "MISSING"
             elif name not in old: status = "NEW"
             elif old[name] != now[name]: status = "CHANGED"
             else:                 status = "ok"
             bad += status != "ok"
             print(f"{status:8} {name}")
         sys.exit(1 if bad else 0)
     with open(args.output, "w", newline="") as f:

                        ETHICAL HACKING MADE SIMPLE

              w = csv.writer(f); w.writerow(["file", "sha256"])
              w.writerows(now.items())
          print(f"hashed {len(now)} files -> {args.output}")

      if __name__ == "__main__":
          main()

     Make a small evidence folder, hash it, change a file, and verify again:

      $ mkdir -p evidence/scans
      $ nano evidence/scans/lab-scan.xml       # use the XML from Lab
      5.4
      $ nano evidence/ssh-events.txt           # use the log from Lab
      5.5
      $ python3 hash_manifest.py evidence -o manifest.csv
      $ python3 hash_manifest.py evidence --verify manifest.csv
      $ echo "edited" >> evidence/ssh-events.txt; touch
      evidence/notes.txt
      $ python3 hash_manifest.py evidence --verify manifest.csv; echo
      "exit code: $?"

     Real output:

      hashed 2 files -> manifest.csv
      ok       scans/lab-scan.xml
      ok       ssh-events.txt
      NEW      notes.txt
      ok       scans/lab-scan.xml
      CHANGED ssh-events.txt
      exit code: 1

     Read the result. The tool flagged one changed file and one new file.
     Your hash values match this book's only if your files are byte-for-
     byte identical; what matters is that verify reports ok before the
     edit and CHANGED after it.

         FROM SAFE CYBER RANGES TO PROFESSIONAL REPORTS

L A B 5. 4 · PA R S E A N N M A P X M L F I L E , T H E N T E S T T H E PA R S E R

Machine: Kali · Time: 30 minutes · Evidence file: nmap_reader.py ,
test_nmap_reader.py

Nmap can write results as XML ( -oX ). Reading that XML with code
beats copying numbers by eye. Save this sample as lab-scan.xml (a
hand-written sample in Nmap's format, so you can practice before
you run Chapter 7's scan):

 <?xml version="1.0"?>
 <nmaprun scanner="nmap" args="nmap -sT -sV -oX lab-scan.xml
 192.168.56.20">
 <host><status state="up"/><address addr="192.168.56.20"
 addrtype="ipv4"/>
 <ports>
 <port protocol="tcp" portid="22"><state state="open"/><service
 name="ssh" product="OpenSSH" version="9.6p1"/></port>
 <port protocol="tcp" portid="80"><state state="open"/><service
 name="http" product="Apache httpd" version="2.4.58"/></port>
 <port protocol="tcp" portid="3000"><state state="open"/><service
 name="http" product="Node.js Express framework"/></port>
 <port protocol="tcp" portid="23"><state state="closed"/><service
 name="telnet"/></port>
 </ports></host>
 </nmaprun>

Save the reader as nmap_reader.py :

 # nmap_reader.py - list open ports from an Nmap XML file (nmap -
 oX scan.xml)
 import sys
 import xml.etree.ElementTree as ET
 from pathlib import Path

 def open_services(path):
     root = ET.parse(path).getroot()
     found = []
     for host in root.findall("host"):
         addr = host.find("address")
         ip = addr.get("addr", "unknown") if addr is not None
 else "unknown"
         for port in host.findall("./ports/port"):
             state = port.find("state")
             if state is None or state.get("state") != "open":
                 continue
             svc = port.find("service")
             found.append({
                 "host": ip,

                       ETHICAL HACKING MADE SIMPLE

                       "protocol": port.get("protocol", ""),
                       "port": int(port.get("portid", "0")),
                       "service": svc.get("name", "unknown") if svc is
      not None else "unknown",
                       "product": (svc.get("product", "") if svc is not
      None else ""),
                  })
          return found

      if __name__ == "__main__":
          if len(sys.argv) != 2:
               raise SystemExit("usage: python3 nmap_reader.py
      SCAN.xml")
          scan = Path(sys.argv[1])
          try:
               for item in open_services(scan):
                   print(item)
          except (OSError, ET.ParseError) as exc:
               raise SystemExit(f"cannot read {scan}: {exc}")
