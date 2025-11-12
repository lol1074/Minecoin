import re
import datetime
version = input("Versione (es. 2.0.1): ").strip()
date = datetime.date.today().isoformat()
features = []
while True:
    f = input("Aggiungi Feature (#FEATURE, #ADDED, #FIX, #TODO, #DOC, ... - vuoto per terminare): ")
    if not f: break
    features.append(f"- {f}")

with open("CHANGELOG.md", "r+") as f:
    old = f.read()
    f.seek(0)
    block = f"## [{version}] - {date}\n" + "\n".join(features) + "\n---\n" + old
    f.write(block)
print("Changelog aggiornato!")
