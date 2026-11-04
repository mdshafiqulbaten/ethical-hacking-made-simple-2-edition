# k8s_review.py
# Auto-extracted from "Ethical Hacking Made Simple (Second Edition)" by Md Shafiqul Baten Sumon.
# Extraction method: text pulled from the book's PDF and, for Python
# files, auto-repaired for indentation. Syntax check: NOT CONFIRMED - please review.
# Review before running, especially if the status above is not "passed".

 # k8s_review.py - flag risky settings in a Kubernetes pod spec
 (JSON form)
 import json, sys

 pod = json.load(open(sys.argv[1]))
 spec = pod["spec"]
 for c in spec["containers"]:
     sc = c.get("securityContext", {})
     checks = {
         "privileged container": sc.get("privileged") is True,
         "runs as root": sc.get("runAsNonRoot") is not True,
         "writable root filesystem":
 sc.get("readOnlyRootFilesystem") is not True,
         "image uses :latest tag": c["image"].endswith(":latest")
 or ":" not in c["image"],
     }
     print(c["name"])
     for name, bad in checks.items():
         print(f" {'REVIEW' if bad else 'ok     '} {name}")
 if spec.get("hostNetwork"):
     print("REVIEW pod uses the host network")

 $ python3 k8s_review.py pod.json

Real output:

 web
   REVIEW       privileged container
   REVIEW       runs as root
   REVIEW       writable root filesystem
   REVIEW       image uses :latest tag
 api

                          ETHICAL HACKING MADE SIMPLE

      ok         privileged container
      ok         runs as root
      ok         writable root filesystem
      ok         image uses :latest tag

  Read the result. The web container fails all four checks: it runs priv‐
  ileged (essentially equivalent to root on the host, not just inside the
  container), as root, with a writable filesystem, and pulls whatever
  image currently happens to be tagged :latest rather than a fixed,
  auditable version. The api container, written with explicit security
  settings, passes every check. This pair is a useful before/after to
  show a client: the difference is a handful of configuration lines, not a
  rewrite.

  L A B 2 2 .3 · W R I T E O N E F I N D I N G T H AT T I E S I A M A N D C O N TA I N E R
  R E S U LT S TO G E T H E R

  Machine: notebook · Time: 15 minutes · Evidence file: cloud-
  finding.md

  Using the finding template from Lab 8.3, write one finding for the
  web container's combination of privileged: true and the :latest
  tag specifically (not every issue found in this chapter). Explain in the
  risk section why combining these two particular settings matters: a
  privileged container pulling an unpinned, frequently changing image
  means the next deployment could silently introduce a new vulnera‐
  bility into a container that already has elevated host access, and no‐
  body would necessarily notice the image had changed.

  What good looks like: the finding is specific to this one combination
  rather than a general "containers should be hardened" statement,
  and the recommendation names both fixes (remove privileged , pin
  to a specific version tag).

Key Takeaways
  Cloud and container misconfigurations, not sophisticated ex‐
  ploits, cause most reported cloud incidents.

          FROM SAFE CYBER RANGES TO PROFESSIONAL REPORTS

   A wildcard IAM permission is not automatically wrong, but it al‐
   ways deserves a specific justification.
   Not every "REVIEW" flag carries the same severity — a read-only
   metadata permission is not the same risk as a full-service
   wildcard.
   Reviewing configuration as code (JSON, not a console) lets you
   check many resources quickly and consistently.
   A container's privileged , root, writable-filesystem, and image-
   tag settings are four independent, checkable risks.

Reflection Questions
1. Why is a wildcard resource on a read-only action treated differ‐
   ently from a wildcard on a write or delete action?
2. What specifically makes the combination of privileged: true
   and an unpinned :latest tag worse than either alone?
3. Why might reviewing configuration as JSON be more reliable
   than clicking through a cloud console by eye?

Next you will look at malicious software itself: how to triage a suspicious
file safely, without running it.

                        ETHICAL HACKING MADE SIMPLE
