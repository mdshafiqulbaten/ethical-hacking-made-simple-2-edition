# header_check_web.py
# Auto-extracted from "Ethical Hacking Made Simple (Second Edition)" by Md Shafiqul Baten Sumon.
# Extraction method: text pulled from the book's PDF and, for Python
# files, auto-repaired for indentation. Syntax check: NOT CONFIRMED - please review.
# Review before running, especially if the status above is not "passed".

 # header_check_web.py - report missing security headers for one
 URL
 # usage: python3 header_check_web.py URL [cookie-string]
 import sys, urllib.request

 WANTED = ["Content-Security-Policy", "X-Content-Type-Options",
           "Strict-Transport-Security", "X-Frame-Options"]

 req = urllib.request.Request(sys.argv[1], method="GET")
 if len(sys.argv) > 2:
     req.add_header("Cookie", sys.argv[2])
 with urllib.request.urlopen(req, timeout=5) as r:
     headers = {k.lower() for k in r.headers.keys()}
 for h in WANTED:
     print(f"{'present' if h.lower() in headers else 'MISSING':8}
 {h}")

To get a cookie for the fixed app, log in first and paste the
session=... value into the second argument. Then run:

 $ python3 header_check_web.py "http://127.0.0.1:5000/search?
 q=lab"
 $ python3 header_check_web.py "http://127.0.0.1:5001/search?
 q=lab" "session=PASTE_VALUE"

Real output:

 MISSING     Content-Security-Policy
 MISSING     X-Content-Type-Options
 MISSING     Strict-Transport-Security
 MISSING     X-Frame-Options

 (fixed app, with a valid session cookie)
 present Content-Security-Policy
 present X-Content-Type-Options
 MISSING Strict-Transport-Security
 MISSING X-Frame-Options

Read the result. The fixed app closed two gaps but still lacks two
headers. Strict-Transport-Security only makes sense over
HTTPS, so its absence on a local HTTP lab is expected; say so rather

                     ETHICAL HACKING MADE SIMPLE

  than reporting it. X-Frame-Options is a genuine remaining gap. A
  good tester separates expected here from worth fixing.

  QUICK CHALLENGE

  A response has status 403 for /admin when you are logged out and
  200 when logged in as a normal student. What is the likely problem,
  and what do you need before you call it a finding?

  Suggested answer: The page may be reachable by a user who should
  not have it (broken access control). Before calling it a finding, con‐
  firm what the 200 page shows (does it expose admin functions or
  data?) and check the role you were given. Chapter 12 covers this in
  depth.

Key Takeaways
  A request has a method, path, headers, and a body; a response
  has a status, headers, and a body.
  Query strings and form fields are input you control and a tester
  must question.
  Missing security headers are cheap hardening findings, not
  emergencies.
  Compare before and after with the same command so your retest
  is evidence.
  Separate "expected in this environment" from "worth fixing".

Reflection Questions
1. Which status code would you expect for a user who is logged in
   but not allowed to see a page?
2. Why is HttpOnly useful on a session cookie?
3. Why might a missing HSTS header on a local lab not be worth
  reporting?

          FROM SAFE CYBER RANGES TO PROFESSIONAL REPORTS

Next you will test the login and session system itself, the front door of most
applications.

                        ETHICAL HACKING MADE SIMPLE
