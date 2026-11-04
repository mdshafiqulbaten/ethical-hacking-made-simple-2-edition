# iam_review.py
# Auto-extracted from "Ethical Hacking Made Simple (Second Edition)" by Md Shafiqul Baten Sumon.
# Extraction method: text pulled from the book's PDF and, for Python
# files, auto-repaired for indentation. Syntax check: NOT CONFIRMED - please review.
# Review before running, especially if the status above is not "passed".

  # iam_review.py - flag over-broad statements in a cloud IAM pol‐
  icy (JSON)
  import json, sys

  policy = json.load(open(sys.argv[1]))
  for i, st in enumerate(policy["Statement"], 1):
      actions = st["Action"] if isinstance(st["Action"], list)
  else [st["Action"]]
      resources = st["Resource"] if isinstance(st["Resource"],
  list) else [st["Resource"]]
      problems = []
      if st["Effect"] == "Allow" and any(a == "*" or
  a.endswith(":*") for a in actions):
          problems.append("wildcard action")
      if st["Effect"] == "Allow" and "*" in resources:
          problems.append("wildcard resource")
      if st.get("Principal") == "*":
          problems.append("any principal")
      print(f"statement {i}: {'REVIEW - ' + ', '.join(problems) if
  problems else 'ok'}")

  $ python3 iam_review.py policy.json

 Real output:

  statement 1: ok
  statement 2: REVIEW - wildcard action, wildcard resource

                      ETHICAL HACKING MADE SIMPLE

      statement 3: REVIEW - wildcard resource

  Read the result. Statement 1 grants exactly one action on exactly
  one resource pattern — the model to aim for. Statement 2 grants ev‐
  ery S3 action on every resource, which is worth questioning directly
  with whoever owns it: does this identity really need to delete and
  modify every object in every bucket, or was this written broadly out
  of convenience? Statement 3's wildcard resource on
  ec2:DescribeInstances is lower-severity: that action only reads in‐
  stance metadata and cannot itself change or expose data, so
  "REVIEW" here means look at it, not this is automatically a serious
  finding — a distinction worth stating explicitly in your writeup so
  the client does not over- or under-react to the flag.

         FROM SAFE CYBER RANGES TO PROFESSIONAL REPORTS

L A B 2 2 . 2 · R E V I E W A C O N TA I N E R ' S S E C U R I T Y S E T T I N G S

Machine: Kali · Time: 20 minutes · Evidence file: k8s_review.py ,
k8s-review.txt
