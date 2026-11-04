# log_timeline.py
# Auto-extracted from "Ethical Hacking Made Simple (Second Edition)" by Md Shafiqul Baten Sumon.
# Extraction method: text pulled from the book's PDF and, for Python
# files, auto-repaired for indentation. Syntax check: NOT CONFIRMED - please review.
# Review before running, especially if the status above is not "passed".

 # log_timeline.py - turn SSH log lines into a simple CSV time‐
 line
 # usage: python3 log_timeline.py ssh-events.txt -o ssh-
 timeline.csv
 import argparse, csv, re

 PATTERN = re.compile(
     r"^(?P<time>\w{3}\s+\d+\s[\d:]{8}) (?P<host>\S+) sshd\
 [\d+\]: "
     r"(?P<event>Failed password|Accepted password|Accepted pub‐
 lickey) "
     r"for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)")

 def main():
     ap = argparse.ArgumentParser()
     ap.add_argument("log"); ap.add_argument("-o", "--output",
 required=True)
     args = ap.parse_args()
     rows = []
     with open(args.log) as f:

                      ETHICAL HACKING MADE SIMPLE

              for line in f:
                  m = PATTERN.match(line)
                  if m:
                      rows.append([m["time"], m["host"], m["event"],
      m["user"], m["ip"]])
          with open(args.output, "w", newline="") as out:
              w = csv.writer(out)
              w.writerow(["time", "host", "event", "user",
      "source_ip"])
              w.writerows(rows)
          fails = sum(r[2] == "Failed password" for r in rows)
          print(f"{len(rows)} events written, {fails} failed logins")

      if __name__ == "__main__":
          main()
