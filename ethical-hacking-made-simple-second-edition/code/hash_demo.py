# hash_demo.py
# Auto-extracted from "Ethical Hacking Made Simple (Second Edition)" by Md Shafiqul Baten Sumon.
# Extraction method: text pulled from the book's PDF and, for Python
# files, auto-repaired for indentation. Syntax check: passed.
# Review before running, especially if the status above is not "passed".

# hash_demo.py - why password storage needs salts and slow
hashes
import hashlib, os, time

for text in ["summer2024", "summer2024."]:
    print(f"sha256({text!r}) =",
hashlib.sha256(text.encode()).hexdigest()[:32], "...")

# Cracking an unsalted MD5 hash with a wordlist (the hashes from
