#!/usr/bin/env python3

import re
import os
import sys
import argparse
import readline
import datetime
from typing import List, Dict, Optional

SETTINGS = {
    "default_changelog": "CHANGELOG.md",
    "max_results": 30,
    "context_lines": 3,
    "color_output": True,
    "show_tags_in_results": True,
    "supported_tags": ["#FIX", "#ADDED", "#REMOVED", "#CHANGED", "#SECURITY", "#DOC", "#TODO", "#FEATURE"],
    "date_format": "%Y-%m-%d",
    "history_file": os.path.expanduser("~/.changelog_search_history"),
}

def color(text, code):
    if not SETTINGS["color_output"]:
        return text
    return f"\033[{code}m{text}\033[0m"

def green(text): return color(text, "32")
def yellow(text): return color(text, "33")
def blue(text): return color(text, "34")
def red(text): return color(text, "31")
def bold(text): return color(text, "1")
def cyan(text): return color(text, "36")
def magenta(text): return color(text, "35")

class ChangelogEntry:
    def __init__(self, version, date, content, tags=None):
        self.version = version
        self.date = date
        self.content = content.strip()
        self.tags = tags or set()
        self.parse_tags()

    def parse_tags(self):
        found_tags = set()
        for tag in SETTINGS['supported_tags']:
            if tag.lower() in self.content.lower():
                found_tags.add(tag)
        self.tags = found_tags

    def __str__(self):
        tags_str = " ".join(sorted(self.tags))
        return f"{bold(self.version)} ({yellow(self.date)}) {magenta(tags_str)}\n{self.content}"

def parse_changelog(filename: str) -> List[ChangelogEntry]:
    with open(filename, encoding='utf-8') as f:
        content = f.read()
    pattern = r'^##\s*\[(.*?)\](?:\s*-\s*([0-9]{4}-[0-9]{2}-[0-9]{2}))?\s*\n((?:.|\n)*?)(?=^##\s*\[|\Z)'
    matches = re.findall(pattern, content, re.MULTILINE)
    entries = []
    for version, date, block in matches:
        date = date or "N/A"
        entries.append(ChangelogEntry(version.strip(), date.strip(), block))
    return entries

def search_by_keyword(entries, keyword, tag_mode=False):
    results = []
    for entry in entries:
        if tag_mode:
            if any(tag for tag in entry.tags if keyword.lower() in tag.lower()):
                results.append(entry)
        else:
            if keyword.lower() in entry.content.lower() or keyword.lower() in entry.version.lower():
                results.append(entry)
    return results

def search_by_date(entries, date_str):
    results = []
    for entry in entries:
        if entry.date == date_str:
            results.append(entry)
    return results

def search_by_version(entries, version):
    for entry in entries:
        if entry.version.lower() == version.lower():
            return entry
    return None

def list_tags(entries):
    tags = set()
    for entry in entries:
        tags.update(entry.tags)
    return sorted(tags)

def print_entry(entry, show_content=True):
    print(bold(cyan(f"==> {entry.version}")) + f" {yellow(f'({entry.date})')}")
    if entry.tags:
        print(magenta(f"Tags: {' '.join(sorted(entry.tags))}"))
    if show_content:
        print(entry.content)
    print("-" * 40)

def print_entries(entries, limit=None):
    count = 0
    for entry in entries:
        print_entry(entry, show_content=False)
        count += 1
        if limit and count >= limit:
            print(f"... Mostrati solo i primi {limit} risultati.")
            break

def choose_entry(entries):
    if not entries:
        print(red("Nessun risultato trovato."))
        return None
    print(green(f"\n{len(entries)} risultati trovati:"))
    for idx, entry in enumerate(entries, 1):
        tagstr = f" [{', '.join(sorted(entry.tags))}]" if entry.tags else ""
        print(f"{idx}. {bold(entry.version)} {yellow(f'({entry.date})')}{magenta(tagstr)}")
    while True:
        try:
            sel = input(cyan("Seleziona un numero per vedere il dettaglio (0 per annullare): "))
            if not sel.isdigit() or int(sel) < 0 or int(sel) > len(entries):
                print(red("Selezione non valida."))
                continue
            if int(sel) == 0:
                return None
            return entries[int(sel) - 1]
        except KeyboardInterrupt:
            print("\nUscita.")
            return None

class InteractiveShell:
    def __init__(self, entries: List[ChangelogEntry], filename: str):
        self.entries = entries
        self.filename = filename
        self.prompt = bold(green("Changelog> "))
        self.running = True
        self.last_results = []

    def print_help(self):
        print("""
Comandi disponibili:
 - help                : mostra questo messaggio
 - cerca <termine>     : cerca per parola chiave libera
 - tag <tag>           : cerca per tag (#FIX, #ADDED, etc.)
 - version <ver>       : mostra il dettaglio di una versione
 - data <YYYY-MM-DD>   : cerca per data
 - lista               : mostra tutte le versioni trovate
 - tags                : mostra tutti i tag utilizzati
 - mostra <num>        : mostra il dettaglio del risultato N dell'ultima ricerca
 - file <path>         : cambia file changelog
 - impostazioni        : mostra le impostazioni attuali
 - esci                : termina la shell
""")

    def run(self):
        print(green("Shell interattiva Changelog"))
        print(cyan(f"File analizzato: {self.filename}"))
        self.print_help()
        while self.running:
            try:
                cmd = input(self.prompt).strip()
                if not cmd:
                    continue
                self.handle_command(cmd)
            except KeyboardInterrupt:
                print("\nUscita dalla shell.")
                break

    def handle_command(self, cmd: str):
        args = cmd.split()
        if not args:
            return
        cmd_name = args[0].lower()

        if cmd_name == "help":
            self.print_help()
        elif cmd_name == "cerca" and len(args) > 1:
            keyword = " ".join(args[1:])
            self.last_results = search_by_keyword(self.entries, keyword)
            print_entries(self.last_results, limit=SETTINGS["max_results"])
        elif cmd_name == "tag" and len(args) > 1:
            tag = args[1].upper() if args[1].startswith("#") else "#" + args[1].upper()
            self.last_results = search_by_keyword(self.entries, tag, tag_mode=True)
            print_entries(self.last_results, limit=SETTINGS["max_results"])
        elif cmd_name == "version" and len(args) > 1:
            ver = " ".join(args[1:])
            entry = search_by_version(self.entries, ver)
            if entry:
                print_entry(entry)
            else:
                print(red("Versione non trovata."))
        elif cmd_name == "data" and len(args) > 1:
            self.last_results = search_by_date(self.entries, args[1])
            print_entries(self.last_results, limit=SETTINGS["max_results"])
        elif cmd_name == "lista":
            print_entries(self.entries, limit=SETTINGS["max_results"])
        elif cmd_name == "tags":
            tags = list_tags(self.entries)
            print(green("Tags trovati: ") + ", ".join(tags))
        elif cmd_name == "mostra" and len(args) > 1 and self.last_results:
            try:
                idx = int(args[1]) - 1
                if idx < 0 or idx >= len(self.last_results):
                    print(red("Indice fuori range."))
                else:
                    print_entry(self.last_results[idx])
            except ValueError:
                print(red("Indice non valido."))
        elif cmd_name == "file" and len(args) > 1:
            newfile = " ".join(args[1:])
            if not os.path.isfile(newfile):
                print(red(f"File non trovato: {newfile}"))
            else:
                self.filename = newfile
                self.entries = parse_changelog(self.filename)
                print(green(f"File cambiato: {self.filename}"))
        elif cmd_name == "impostazioni":
            for k, v in SETTINGS.items():
                print(f"{k}: {v}")
        elif cmd_name == "esci":
            self.running = False
            print(yellow("Arrivederci."))
        else:
            print(red("Comando sconosciuto. Digita 'help' per la lista dei comandi."))

def main():
    parser = argparse.ArgumentParser(description="Changelog Advanced Search CLI")
    parser.add_argument("--file", default=SETTINGS["default_changelog"], help="Percorso del file changelog")
    parser.add_argument("--shell", action="store_true", help="Avvia la shell interattiva")
    parser.add_argument("--cerca", type=str, help="Cerca una parola chiave libera")
    parser.add_argument("--tag", type=str, help="Cerca un tag specifico")
    parser.add_argument("--data", type=str, help="Cerca per data YYYY-MM-DD")
    parser.add_argument("--version", type=str, help="Mostra una versione specifica")
    parser.add_argument("--lista", action="store_true", help="Mostra tutte le versioni")
    parser.add_argument("--impostazioni", action="store_true", help="Mostra le impostazioni attuali")

    args = parser.parse_args()

    entries = parse_changelog(args.file)

    if args.shell:  # Modalità shell interattiva
        shell = InteractiveShell(entries, args.file)
        shell.run()
        return

    if args.impostazioni:
        for k, v in SETTINGS.items():
            print(f"{k}: {v}")

    if args.cerca:
        res = search_by_keyword(entries, args.cerca)
        print_entries(res, limit=SETTINGS["max_results"])
    if args.tag:
        tag = args.tag.upper() if args.tag.startswith("#") else "#" + args.tag.upper()
        res = search_by_keyword(entries, tag, tag_mode=True)
        print_entries(res, limit=SETTINGS["max_results"])
    if args.data:
        res = search_by_date(entries, args.data)
        print_entries(res, limit=SETTINGS["max_results"])
    if args.version:
        entry = search_by_version(entries, args.version)
        if entry:
            print_entry(entry)
        else:
            print(red("Versione non trovata."))
    if args.lista:
        print_entries(entries, limit=SETTINGS["max_results"])

    if not (args.cerca or args.tag or args.data or args.version or args.lista or args.impostazioni or args.shell):
        print(yellow("Nessun comando fornito. Usa --shell per avviare la shell interattiva o --help per informazioni."))

if __name__ == "__main__":
    main()