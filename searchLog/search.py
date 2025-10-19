#!/usr/bin/env python3
"""
Sistema Automatico di Tracking Changelog con integrazione GitHub
Traccia modifiche, genera diff, aggiorna changelog automaticamente
"""

import os
import sys
import json
import subprocess
import datetime
import argparse
import re
import readline
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from difflib import unified_diff

# ============================================================================
# CHANGELOG ENTRY PARSER (dal vecchio script)
# ============================================================================

class ChangelogEntry:
    """Entry del changelog parsata"""
    def __init__(self, version, date, content, tags=None):
        self.version = version
        self.date = date
        self.content = content.strip()
        self.tags = tags or set()
        self.parse_tags()

    def parse_tags(self):
        found_tags = set()
        supported_tags = ["#FIX", "#ADDED", "#REMOVED", "#CHANGED", "#SECURITY", 
                         "#DOC", "#TODO", "#FEATURE"]
        for tag in supported_tags:
            if tag.lower() in self.content.lower():
                found_tags.add(tag)
        self.tags = found_tags

    def __str__(self):
        tags_str = " ".join(sorted(self.tags))
        return f"{self.version} ({self.date}) {tags_str}\n{self.content}"

def parse_changelog_file(filename: str) -> List[ChangelogEntry]:
    """Parse il file changelog"""
    if not os.path.exists(filename):
        return []
    
    with open(filename, encoding='utf-8') as f:
        content = f.read()
    
    pattern = r'^##\s*\[(.*?)\](?:\s*-\s*([0-9]{4}-[0-9]{2}-[0-9]{2}))?\s*\n((?:.|\n)*?)(?=^##\s*\[|\Z)'
    matches = re.findall(pattern, content, re.MULTILINE)
    
    entries = []
    for version, date, block in matches:
        date = date or "N/A"
        entries.append(ChangelogEntry(version.strip(), date.strip(), block))
    
    return entries

# ============================================================================
# CONFIGURAZIONE
# ============================================================================

CONFIG = {
    "changelog_file": "CHANGELOG.md",
    "tracking_db": ".changelog_tracking.json",
    "github_repo": None,  # Formato: "username/repo"
    "github_token": None,  # Token per API GitHub (opzionale)
    "auto_detect_repo": True,
    "max_diff_lines": 100,
    "excluded_files": [".git", "__pycache__", "*.pyc", ".changelog_tracking.json"],
    "default_tags": ["#CHANGED"],
    "color_output": True,
    "history_file": os.path.expanduser("~/.changelog_tracker_history"),
}

# ============================================================================
# COLOR HELPERS
# ============================================================================

def color(text, code):
    if not CONFIG["color_output"]:
        return text
    return f"\033[{code}m{text}\033[0m"

def green(text): return color(text, "32")
def yellow(text): return color(text, "33")
def blue(text): return color(text, "34")
def red(text): return color(text, "31")
def bold(text): return color(text, "1")
def cyan(text): return color(text, "36")
def magenta(text): return color(text, "35")

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class FileChange:
    """Rappresenta una modifica a un file"""
    filepath: str
    change_type: str  # "added", "modified", "deleted"
    author: str
    timestamp: str
    commit_hash: Optional[str] = None
    pr_number: Optional[int] = None
    pr_url: Optional[str] = None
    diff_snippet: Optional[str] = None
    lines_added: int = 0
    lines_removed: int = 0
    
    def to_dict(self):
        return asdict(self)

@dataclass
class ChangelogUpdate:
    """Rappresenta un aggiornamento da scrivere nel changelog"""
    version: str
    date: str
    changes: List[FileChange]
    tags: List[str]
    description: str
    pr_info: Optional[Dict] = None

# ============================================================================
# GIT OPERATIONS
# ============================================================================

class GitHelper:
    """Helper per operazioni Git"""
    
    @staticmethod
    def is_git_repo() -> bool:
        """Verifica se siamo in un repo git"""
        try:
            subprocess.run(["git", "rev-parse", "--git-dir"], 
                         capture_output=True, check=True)
            return True
        except:
            return False
    
    @staticmethod
    def get_repo_url() -> Optional[str]:
        """Ottiene l'URL del repository GitHub"""
        try:
            result = subprocess.run(
                ["git", "config", "--get", "remote.origin.url"],
                capture_output=True, text=True, check=True
            )
            url = result.stdout.strip()
            # Converte SSH/HTTPS in formato username/repo
            if "github.com" in url:
                match = re.search(r'github\.com[:/](.+/.+?)(?:\.git)?$', url)
                if match:
                    return match.group(1)
            return None
        except:
            return None
    
    @staticmethod
    def get_current_branch() -> str:
        """Ottiene il branch corrente"""
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True, text=True, check=True
            )
            return result.stdout.strip()
        except:
            return "unknown"
    
    @staticmethod
    def get_last_commit_info() -> Tuple[str, str, str]:
        """Ottiene info sull'ultimo commit (hash, author, date)"""
        try:
            hash_result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                capture_output=True, text=True, check=True
            )
            author_result = subprocess.run(
                ["git", "log", "-1", "--pretty=format:%an"],
                capture_output=True, text=True, check=True
            )
            date_result = subprocess.run(
                ["git", "log", "-1", "--pretty=format:%ci"],
                capture_output=True, text=True, check=True
            )
            return (
                hash_result.stdout.strip()[:7],
                author_result.stdout.strip(),
                date_result.stdout.strip()
            )
        except:
            return ("unknown", "unknown", datetime.datetime.now().isoformat())
    
    @staticmethod
    def get_file_diff(filepath: str, max_lines: int = 100) -> Tuple[str, int, int]:
        """Ottiene il diff di un file rispetto al commit precedente"""
        try:
            result = subprocess.run(
                ["git", "diff", "HEAD~1", "HEAD", "--", filepath],
                capture_output=True, text=True
            )
            diff = result.stdout
            
            # Conta linee aggiunte/rimosse
            added = len([l for l in diff.split('\n') if l.startswith('+')])
            removed = len([l for l in diff.split('\n') if l.startswith('-')])
            
            # Limita il numero di linee del diff
            lines = diff.split('\n')
            if len(lines) > max_lines:
                diff = '\n'.join(lines[:max_lines]) + f"\n... (troncato, {len(lines) - max_lines} linee)"
            
            return diff, added, removed
        except:
            return "", 0, 0
    
    @staticmethod
    def get_changed_files() -> List[str]:
        """Ottiene la lista dei file modificati rispetto all'ultimo commit"""
        try:
            result = subprocess.run(
                ["git", "diff", "--name-only", "HEAD~1", "HEAD"],
                capture_output=True, text=True, check=True
            )
            return [f.strip() for f in result.stdout.split('\n') if f.strip()]
        except:
            return []

# ============================================================================
# TRACKING DATABASE
# ============================================================================

class ChangeTracker:
    """Gestisce il database di tracking delle modifiche"""
    
    def __init__(self, db_path: str = ".changelog_tracking.json"):
        self.db_path = db_path
        self.data = self._load()
    
    def _load(self) -> Dict:
        """Carica il database"""
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {"changes": [], "last_update": None}
        return {"changes": [], "last_update": None}
    
    def _save(self):
        """Salva il database"""
        with open(self.db_path, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)
    
    def add_change(self, change: FileChange):
        """Aggiunge una modifica al tracking"""
        self.data["changes"].append(change.to_dict())
        self.data["last_update"] = datetime.datetime.now().isoformat()
        self._save()
    
    def get_pending_changes(self) -> List[FileChange]:
        """Ottiene le modifiche non ancora aggiunte al changelog"""
        changes = []
        for c in self.data.get("changes", []):
            changes.append(FileChange(**c))
        return changes
    
    def clear_changes(self):
        """Pulisce le modifiche dopo averle aggiunte al changelog"""
        self.data["changes"] = []
        self._save()

# ============================================================================
# CHANGELOG MANAGER
# ============================================================================

class ChangelogManager:
    """Gestisce le operazioni sul file CHANGELOG.md"""
    
    def __init__(self, filepath: str = "CHANGELOG.md"):
        self.filepath = filepath
        self.content = self._read()
    
    def _read(self) -> str:
        """Legge il changelog"""
        if os.path.exists(self.filepath):
            with open(self.filepath, 'r', encoding='utf-8') as f:
                return f.read()
        return "# Changelog\n\n"
    
    def _write(self, content: str):
        """Scrive il changelog"""
        with open(self.filepath, 'w', encoding='utf-8') as f:
            f.write(content)
    
    def add_entry(self, update: ChangelogUpdate, github_repo: Optional[str] = None):
        """Aggiunge una nuova entry al changelog"""
        
        # Genera la sezione delle modifiche
        changes_text = self._format_changes(update.changes, github_repo)
        
        # Genera la entry completa
        entry = f"\n## [{update.version}] - {update.date}\n"
        entry += f"### {' '.join(update.tags)}\n"
        
        if update.description:
            entry += f"- {update.description}\n\n"
        
        if update.pr_info:
            pr_num = update.pr_info.get("number")
            pr_url = update.pr_info.get("url")
            pr_author = update.pr_info.get("author", "unknown")
            entry += f"**Pull Request**: [#{pr_num}]({pr_url}) by @{pr_author}\n\n"
        
        entry += changes_text
        entry += "\n---\n"
        
        # Inserisce la entry nel changelog
        # Cerca la posizione di [Unreleased] o inserisce all'inizio
        unreleased_match = re.search(r'##\s*\[Unreleased\].*?(?=##\s*\[|\Z)', 
                                     self.content, re.DOTALL)
        
        if unreleased_match:
            # Inserisce dopo [Unreleased]
            insert_pos = unreleased_match.end()
            new_content = (
                self.content[:insert_pos] + 
                entry + 
                self.content[insert_pos:]
            )
        else:
            # Inserisce all'inizio dopo il titolo
            lines = self.content.split('\n')
            if lines[0].startswith('#'):
                new_content = '\n'.join(lines[:2]) + '\n' + entry + '\n'.join(lines[2:])
            else:
                new_content = entry + self.content
        
        self._write(new_content)
        print(f"✅ Changelog aggiornato: {self.filepath}")
    
    def _format_changes(self, changes: List[FileChange], github_repo: Optional[str]) -> str:
        """Formatta le modifiche per il changelog"""
        if not changes:
            return ""
        
        text = "**File modificati:**\n"
        
        for change in changes:
            icon = self._get_change_icon(change.change_type)
            
            # Link al file su GitHub
            if github_repo and change.commit_hash:
                file_url = f"https://github.com/{github_repo}/blob/{change.commit_hash}/{change.filepath}"
                diff_url = f"https://github.com/{github_repo}/commit/{change.commit_hash}"
                text += f"- {icon} [`{change.filepath}`]({file_url}) "
                text += f"([diff]({diff_url}))\n"
            else:
                text += f"- {icon} `{change.filepath}`\n"
            
            # Aggiungi statistiche
            if change.lines_added > 0 or change.lines_removed > 0:
                text += f"  - `+{change.lines_added} -{change.lines_removed}` linee\n"
            
            # Aggiungi autore e timestamp
            text += f"  - Modificato da: **{change.author}** il {change.timestamp[:10]}\n"
            
            # Aggiungi snippet del diff (se presente e non troppo lungo)
            if change.diff_snippet and len(change.diff_snippet) < 500:
                text += f"  <details><summary>Anteprima modifiche</summary>\n\n```diff\n{change.diff_snippet}\n```\n</details>\n"
        
        return text + "\n"
    
    @staticmethod
    def _get_change_icon(change_type: str) -> str:
        """Ottiene l'icona per il tipo di modifica"""
        icons = {
            "added": "✨",
            "modified": "🔧",
            "deleted": "🗑️",
            "renamed": "📝"
        }
        return icons.get(change_type, "📄")

# ============================================================================
# INTERACTIVE SHELL
# ============================================================================

class ChangelogShell:
    """Shell interattiva per gestire changelog e modifiche"""
    
    def __init__(self):
        self.tracker = ChangeTracker(CONFIG["tracking_db"])
        self.changelog = ChangelogManager(CONFIG["changelog_file"])
        self.github_repo = CONFIG.get("github_repo") or GitHelper.get_repo_url()
        self.prompt = bold(green("Changelog-Tracker> "))
        self.running = True
        self.last_search_results = []
        self.last_changelog_results = []  # Per ricerca nel changelog
        
        # Configura readline per history
        if os.path.exists(CONFIG["history_file"]):
            readline.read_history_file(CONFIG["history_file"])
    
    def save_history(self):
        """Salva la cronologia dei comandi"""
        readline.write_history_file(CONFIG["history_file"])
    
    def print_help(self):
        """Mostra l'aiuto"""
        print(f"""
{bold(cyan('=== COMANDI TRACKING ==='))}
  {green('track')}              : Traccia modifiche dall'ultimo commit
  {green('status')}             : Mostra modifiche in attesa
  {green('pending')}            : Lista dettagliata modifiche in attesa
  {green('clear')}              : Pulisce modifiche tracciate
  {green('commit')}             : Committa modifiche al changelog

{bold(cyan('=== COMANDI RICERCA MODIFICHE TRACCIATE ==='))}
  {green('cerca <termine>')}    : Cerca modifiche per file/autore/descrizione
  {green('file <path>')}        : Cerca modifiche per file specifico
  {green('autore <nome>')}      : Cerca modifiche per autore
  {green('data <YYYY-MM-DD>')}  : Cerca modifiche per data

{bold(cyan('=== COMANDI RICERCA NEL CHANGELOG ==='))}
  {green('changelog-cerca <termine>')} : Cerca nel changelog per keyword
  {green('changelog-tag <tag>')}       : Cerca nel changelog per tag (#FIX, #ADDED, ecc.)
  {green('changelog-versione <ver>')}  : Mostra una versione specifica
  {green('changelog-data <YYYY-MM-DD>')}: Cerca nel changelog per data
  {green('changelog-lista')}           : Lista tutte le versioni del changelog

{bold(cyan('=== COMANDI VISUALIZZAZIONE ==='))}
  {green('mostra <num>')}       : Mostra dettaglio modifica N dall'ultima ricerca
  {green('diff <num>')}         : Mostra diff completo della modifica N
  {green('changelog')}          : Visualizza changelog completo (prime 50 righe)
  {green('versioni')}           : Lista tutte le versioni nel changelog

{bold(cyan('=== COMANDI CONFIGURAZIONE ==='))}
  {green('repo <user/repo>')}   : Imposta repository GitHub
  {green('config')}             : Mostra configurazione corrente
  {green('help')}               : Mostra questo messaggio
  {green('esci')}               : Termina la shell
""")
    
    def run(self):
        """Avvia la shell interattiva"""
        print(bold(green("\n🚀 Changelog Tracker - Shell Interattiva")))
        print(cyan(f"Repository: {self.github_repo or 'Non configurato'}"))
        print(cyan(f"Changelog: {CONFIG['changelog_file']}"))
        print(yellow("\nDigita 'help' per vedere i comandi disponibili\n"))
        
        while self.running:
            try:
                cmd = input(self.prompt).strip()
                if not cmd:
                    continue
                self.handle_command(cmd)
            except KeyboardInterrupt:
                print("\n" + yellow("Usa 'esci' per terminare"))
            except EOFError:
                print("\n" + yellow("Arrivederci!"))
                break
        
        self.save_history()
    
    def handle_command(self, cmd: str):
        """Gestisce i comandi"""
        args = cmd.split(maxsplit=1)
        cmd_name = args[0].lower()
        cmd_arg = args[1] if len(args) > 1 else ""
        
        # === COMANDI TRACKING ===
        if cmd_name == "track":
            self.cmd_track()
        elif cmd_name == "status":
            self.cmd_status()
        elif cmd_name == "pending":
            self.cmd_pending()
        elif cmd_name == "clear":
            self.cmd_clear()
        elif cmd_name == "commit":
            self.cmd_commit()
        
        # === COMANDI RICERCA ===
        elif cmd_name == "cerca" and cmd_arg:
            self.cmd_search(cmd_arg)
        elif cmd_name == "file" and cmd_arg:
            self.cmd_search_file(cmd_arg)
        elif cmd_name == "autore" and cmd_arg:
            self.cmd_search_author(cmd_arg)
        elif cmd_name == "data" and cmd_arg:
            self.cmd_search_date(cmd_arg)
        elif cmd_name == "tag" and cmd_arg:
            self.cmd_search_tag(cmd_arg)
        
        # === COMANDI RICERCA NEL CHANGELOG ===
        elif cmd_name == "changelog-cerca" and cmd_arg:
            self.cmd_changelog_search(cmd_arg)
        elif cmd_name == "changelog-tag" and cmd_arg:
            self.cmd_changelog_search_tag(cmd_arg)
        elif cmd_name == "changelog-versione" and cmd_arg:
            self.cmd_changelog_version(cmd_arg)
        elif cmd_name == "changelog-data" and cmd_arg:
            self.cmd_changelog_date(cmd_arg)
        elif cmd_name == "changelog-lista":
            self.cmd_changelog_list()
        
        # === COMANDI VISUALIZZAZIONE ===
        elif cmd_name == "mostra" and cmd_arg:
            self.cmd_mostra(cmd_arg)
        elif cmd_name == "diff" and cmd_arg:
            self.cmd_diff(cmd_arg)
        elif cmd_name == "changelog":
            self.cmd_show_changelog()
        elif cmd_name == "versioni":
            self.cmd_versions()
        
        # === COMANDI CONFIGURAZIONE ===
        elif cmd_name == "repo" and cmd_arg:
            self.cmd_set_repo(cmd_arg)
        elif cmd_name == "config":
            self.cmd_config()
        elif cmd_name == "help":
            self.print_help()
        elif cmd_name == "esci" or cmd_name == "exit" or cmd_name == "quit":
            self.running = False
            print(yellow("Arrivederci! 👋"))
        else:
            print(red(f"Comando sconosciuto: '{cmd_name}'. Digita 'help' per aiuto."))
    
    # ========== IMPLEMENTAZIONE COMANDI ==========
    
    def cmd_track(self):
        """Traccia modifiche correnti"""
        if not GitHelper.is_git_repo():
            print(red("❌ Non sei in un repository Git!"))
            return
        
        commit_hash, author, timestamp = GitHelper.get_last_commit_info()
        changed_files = GitHelper.get_changed_files()
        
        if not changed_files:
            print(yellow("ℹ️  Nessun file modificato nell'ultimo commit"))
            return
        
        print(green(f"📝 Trovati {len(changed_files)} file modificati:"))
        
        for filepath in changed_files:
            change_type = "deleted" if not os.path.exists(filepath) else "modified"
            diff, added, removed = GitHelper.get_file_diff(filepath, CONFIG["max_diff_lines"])
            
            change = FileChange(
                filepath=filepath,
                change_type=change_type,
                author=author,
                timestamp=timestamp,
                commit_hash=commit_hash,
                diff_snippet=diff[:500] if diff else None,
                lines_added=added,
                lines_removed=removed
            )
            
            self.tracker.add_change(change)
            print(f"  ✅ {cyan(filepath)} {green(f'+{added}')} {red(f'-{removed}')}")
        
        print(green(f"\n💾 Modifiche salvate!"))
    
    def cmd_status(self):
        """Mostra status"""
        changes = self.tracker.get_pending_changes()
        print(f"\n{bold('📊 Status:')}")
        print(f"Repository: {cyan(self.github_repo or 'N/A')}")
        print(f"Branch: {cyan(GitHelper.get_current_branch())}")
        print(f"Modifiche in attesa: {yellow(str(len(changes)))}\n")
    
    def cmd_pending(self):
        """Lista modifiche in attesa"""
        changes = self.tracker.get_pending_changes()
        
        if not changes:
            print(yellow("✅ Nessuna modifica in attesa"))
            return
        
        # Popola last_search_results per permettere mostra/diff
        self.last_search_results = changes
        
        print(green(f"\n📋 {len(changes)} modifiche in attesa:\n"))
        
        for i, change in enumerate(changes, 1):
            icon = ChangelogManager._get_change_icon(change.change_type)
            print(f"{bold(str(i))}. {icon} {cyan(change.filepath)}")
            print(f"   Tipo: {yellow(change.change_type)}")
            print(f"   Autore: {change.author}")
            print(f"   Data: {change.timestamp[:19]}")
            print(f"   Modifiche: {green(f'+{change.lines_added}')} {red(f'-{change.lines_removed}')}")
            if change.commit_hash:
                print(f"   Commit: {magenta(change.commit_hash)}")
            print()
        
        print(yellow(f"Usa 'mostra <num>' o 'diff <num>' per vedere i dettagli"))
    
    def cmd_clear(self):
        """Pulisce modifiche"""
        confirm = input(yellow("Sei sicuro di voler pulire tutte le modifiche? (s/n): "))
        if confirm.lower() == 's':
            self.tracker.clear_changes()
            print(green("✅ Modifiche pulite"))
        else:
            print(yellow("Operazione annullata"))
    
    def cmd_commit(self):
        """Committa al changelog"""
        changes = self.tracker.get_pending_changes()
        
        if not changes:
            print(yellow("ℹ️  Nessuna modifica da committare"))
            return
        
        print(green(f"📋 {len(changes)} modifiche da committare\n"))
        
        version = input("Versione (es. 1.2.3 o 'Unreleased'): ").strip()
        date = input(f"Data ({datetime.datetime.now().strftime('%Y-%m-%d')}): ").strip()
        date = date or datetime.datetime.now().strftime("%Y-%m-%d")
        
        print(f"\nTag disponibili: {', '.join(CONFIG['default_tags'])}")
        tags_input = input("Tag (separati da spazio): ").strip()
        tags = tags_input.split() if tags_input else CONFIG["default_tags"]
        
        description = input("Descrizione (opzionale): ").strip()
        
        update = ChangelogUpdate(
            version=version,
            date=date,
            changes=changes,
            tags=tags,
            description=description
        )
        
        self.changelog.add_entry(update, self.github_repo)
        self.tracker.clear_changes()
        
        print(green("\n✨ Changelog aggiornato con successo!"))
    
    def cmd_search(self, term: str):
        """Cerca modifiche"""
        changes = self.tracker.get_pending_changes()
        results = [c for c in changes if term.lower() in c.filepath.lower() 
                   or term.lower() in c.author.lower()]
        
        self.last_search_results = results
        self._print_search_results(results, f"Ricerca: '{term}'")
    
    def cmd_search_file(self, filepath: str):
        """Cerca per file"""
        changes = self.tracker.get_pending_changes()
        results = [c for c in changes if filepath in c.filepath]
        
        self.last_search_results = results
        self._print_search_results(results, f"File: '{filepath}'")
    
    def cmd_search_author(self, author: str):
        """Cerca per autore"""
        changes = self.tracker.get_pending_changes()
        results = [c for c in changes if author.lower() in c.author.lower()]
        
        self.last_search_results = results
        self._print_search_results(results, f"Autore: '{author}'")
    
    def cmd_search_date(self, date: str):
        """Cerca per data"""
        changes = self.tracker.get_pending_changes()
        results = [c for c in changes if date in c.timestamp]
        
        self.last_search_results = results
        self._print_search_results(results, f"Data: '{date}'")
    
    def cmd_search_tag(self, tag: str):
        """Cerca per tag nelle modifiche tracciate"""
        changes = self.tracker.get_pending_changes()
        # Tag non si applica alle modifiche tracciate, cerca nel changelog
        print(yellow("ℹ️  I tag si trovano nel CHANGELOG, usa 'changelog-tag <tag>'"))
    
    # ========== COMANDI RICERCA NEL CHANGELOG ==========
    
    def cmd_changelog_search(self, keyword: str):
        """Cerca nel changelog per keyword"""
        entries = parse_changelog_file(CONFIG['changelog_file'])
        
        if not entries:
            print(yellow("⚠️  CHANGELOG.md non trovato o vuoto"))
            return
        
        results = [e for e in entries if keyword.lower() in e.content.lower() 
                   or keyword.lower() in e.version.lower()]
        
        self.last_changelog_results = results
        self._print_changelog_results(results, f"Keyword: '{keyword}'")
    
    def cmd_changelog_search_tag(self, tag: str):
        """Cerca nel changelog per tag"""
        entries = parse_changelog_file(CONFIG['changelog_file'])
        
        if not entries:
            print(yellow("⚠️  CHANGELOG.md non trovato o vuoto"))
            return
        
        tag = tag.upper() if tag.startswith("#") else "#" + tag.upper()
        results = [e for e in entries if tag in e.tags]
        
        self.last_changelog_results = results
        self._print_changelog_results(results, f"Tag: '{tag}'")
    
    def cmd_changelog_version(self, version: str):
        """Mostra versione specifica dal changelog"""
        entries = parse_changelog_file(CONFIG['changelog_file'])
        
        if not entries:
            print(yellow("⚠️  CHANGELOG.md non trovato o vuoto"))
            return
        
        for entry in entries:
            if entry.version.lower() == version.lower():
                self._print_changelog_entry(entry)
                return
        
        print(red(f"Versione '{version}' non trovata"))
    
    def cmd_changelog_date(self, date: str):
        """Cerca nel changelog per data"""
        entries = parse_changelog_file(CONFIG['changelog_file'])
        
        if not entries:
            print(yellow("⚠️  CHANGELOG.md non trovato o vuoto"))
            return
        
        results = [e for e in entries if e.date == date]
        
        self.last_changelog_results = results
        self._print_changelog_results(results, f"Data: '{date}'")
    
    def cmd_changelog_list(self):
        """Lista tutte le versioni del changelog"""
        entries = parse_changelog_file(CONFIG['changelog_file'])
        
        if not entries:
            print(yellow("⚠️  CHANGELOG.md non trovato o vuoto"))
            return
        
        print(green(f"\n📦 {len(entries)} versioni nel CHANGELOG:\n"))
        
        for entry in entries:
            tags_str = " " + magenta(" ".join(sorted(entry.tags))) if entry.tags else ""
            print(f"  • {bold(entry.version)} {yellow(f'({entry.date})')}{tags_str}")
        
        print(yellow(f"\nUsa 'changelog-versione <ver>' per vedere i dettagli"))
    
    def _print_changelog_results(self, results: List[ChangelogEntry], title: str):
        """Stampa risultati ricerca changelog"""
        if not results:
            print(yellow(f"Nessun risultato per: {title}"))
            return
        
        print(green(f"\n🔍 {len(results)} risultati nel CHANGELOG per: {title}\n"))
        
        for i, entry in enumerate(results, 1):
            tags_str = " " + magenta(" ".join(sorted(entry.tags))) if entry.tags else ""
            print(f"{bold(str(i))}. {bold(entry.version)} {yellow(f'({entry.date})')}{tags_str}")
            
            # Mostra preview del contenuto (prime 100 char)
            preview = entry.content[:100].replace('\n', ' ')
            if len(entry.content) > 100:
                preview += "..."
            print(f"   {preview}\n")
        
        print(yellow(f"Usa 'changelog-versione <ver>' per vedere i dettagli completi"))
    
    def _print_changelog_entry(self, entry: ChangelogEntry):
        """Stampa dettaglio entry changelog"""
        print(f"\n{bold(cyan(f'=== {entry.version} ==='))}")
        print(f"Data: {yellow(entry.date)}")
        
        if entry.tags:
            print(f"Tags: {magenta(' '.join(sorted(entry.tags)))}")
        
        print(f"\n{entry.content}\n")
        print("-" * 60)
    
    def cmd_search_tag_old(self, tag: str):
        """Cerca nel changelog per tag"""
        # Importa il parser dal vecchio script
        print(yellow("🔍 Ricerca nel changelog..."))
        try:
            with open(CONFIG['changelog_file'], 'r', encoding='utf-8') as f:
                content = f.read()
            
            if tag.upper() in content:
                # Trova le sezioni con il tag
                lines = content.split('\n')
                results = []
                for i, line in enumerate(lines):
                    if tag.upper() in line:
                        # Stampa contesto
                        start = max(0, i - 2)
                        end = min(len(lines), i + 10)
                        print(cyan("\n--- Trovato ---"))
                        for j in range(start, end):
                            if j == i:
                                print(yellow(lines[j]))
                            else:
                                print(lines[j])
                print()
            else:
                print(yellow(f"Nessun risultato per tag '{tag}'"))
        except Exception as e:
            print(red(f"Errore: {e}"))
    
    def cmd_mostra(self, num_str: str):
        """Mostra dettaglio modifica o entry changelog"""
        try:
            num = int(num_str) - 1
            
            # Prova prima con modifiche tracciate
            if self.last_search_results and 0 <= num < len(self.last_search_results):
                change = self.last_search_results[num]
                self._print_change_detail(change)
            # Altrimenti prova con risultati changelog
            elif self.last_changelog_results and 0 <= num < len(self.last_changelog_results):
                entry = self.last_changelog_results[num]
                self._print_changelog_entry(entry)
            else:
                print(red("Indice non valido. Esegui prima una ricerca."))
        except ValueError:
            print(red("Numero non valido"))
    
    def cmd_diff(self, num_str: str):
        """Mostra diff completo"""
        try:
            num = int(num_str) - 1
            if num < 0 or num >= len(self.last_search_results):
                print(red("Indice non valido"))
                return
            
            change = self.last_search_results[num]
            
            if change.diff_snippet:
                print(f"\n{bold(cyan('=== DIFF: ' + change.filepath + ' ==='))}\n")
                print(change.diff_snippet)
                print()
            else:
                print(yellow("Nessun diff disponibile"))
        except ValueError:
            print(red("Numero non valido"))
    
    def cmd_show_changelog(self):
        """Mostra changelog"""
        try:
            with open(CONFIG['changelog_file'], 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Mostra solo le prime 50 righe
            lines = content.split('\n')
            for line in lines[:50]:
                if line.startswith('##'):
                    print(bold(cyan(line)))
                elif line.startswith('###'):
                    print(magenta(line))
                else:
                    print(line)
            
            if len(lines) > 50:
                print(yellow(f"\n... ({len(lines) - 50} righe omesse)"))
        except Exception as e:
            print(red(f"Errore: {e}"))
    
    def cmd_versions(self):
        """Lista versioni dal changelog"""
        try:
            with open(CONFIG['changelog_file'], 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Trova tutte le versioni
            pattern = r'^##\s*\[(.*?)\](?:\s*-\s*([0-9]{4}-[0-9]{2}-[0-9]{2}))?'
            matches = re.findall(pattern, content, re.MULTILINE)
            
            print(green(f"\n📦 Versioni trovate ({len(matches)}):\n"))
            for version, date in matches:
                date_str = f" ({yellow(date)})" if date else ""
                print(f"  • {bold(version)}{date_str}")
            print()
        except Exception as e:
            print(red(f"Errore: {e}"))
    
    def cmd_set_repo(self, repo: str):
        """Imposta repository"""
        self.github_repo = repo
        CONFIG['github_repo'] = repo
        print(green(f"✅ Repository impostato: {repo}"))
    
    def cmd_config(self):
        """Mostra configurazione"""
        print(f"\n{bold('⚙️  Configurazione:')}\n")
        for k, v in CONFIG.items():
            print(f"  {cyan(k)}: {v}")
        print()
    
    def _print_search_results(self, results: List[FileChange], title: str):
        """Stampa risultati ricerca"""
        if not results:
            print(yellow(f"Nessun risultato per: {title}"))
            return
        
        print(green(f"\n🔍 {len(results)} risultati per: {title}\n"))
        
        for i, change in enumerate(results, 1):
            icon = ChangelogManager._get_change_icon(change.change_type)
            print(f"{bold(str(i))}. {icon} {cyan(change.filepath)}")
            print(f"   {change.author} • {change.timestamp[:10]} • "
                  f"{green(f'+{change.lines_added}')} {red(f'-{change.lines_removed}')}")
        
        print(yellow(f"\nUsa 'mostra <num>' per vedere i dettagli"))
    
    def _print_change_detail(self, change: FileChange):
        """Stampa dettaglio modifica"""
        icon = ChangelogManager._get_change_icon(change.change_type)
        
        print(f"\n{bold(cyan('=== DETTAGLIO MODIFICA ==='))}\n")
        print(f"File: {icon} {bold(change.filepath)}")
        print(f"Tipo: {yellow(change.change_type)}")
        print(f"Autore: {change.author}")
        print(f"Data: {change.timestamp}")
        print(f"Modifiche: {green(f'+{change.lines_added}')} {red(f'-{change.lines_removed}')}")
        
        if change.commit_hash:
            print(f"Commit: {magenta(change.commit_hash)}")
            if self.github_repo:
                url = f"https://github.com/{self.github_repo}/commit/{change.commit_hash}"
                print(f"Link: {blue(url)}")
        
        if change.diff_snippet:
            print(f"\n{bold('Anteprima diff:')}")
            print(change.diff_snippet[:300])
            if len(change.diff_snippet) > 300:
                print(yellow("... (troncato, usa 'diff <num>' per vedere tutto)"))
        
        print()

# ============================================================================
# MAIN CLI
# ============================================================================

def track_changes(args):
    """Traccia le modifiche correnti e le aggiunge al database"""
    
    if not GitHelper.is_git_repo():
        print("❌ Non sei in un repository Git!")
        return
    
    # Ottiene informazioni repository
    github_repo = args.github_repo or CONFIG.get("github_repo")
    if not github_repo and CONFIG["auto_detect_repo"]:
        github_repo = GitHelper.get_repo_url()
        if github_repo:
            print(f"📦 Repository rilevato: {github_repo}")
    
    # Ottiene info commit
    commit_hash, author, timestamp = GitHelper.get_last_commit_info()
    
    # Ottiene file modificati
    changed_files = GitHelper.get_changed_files()
    
    if not changed_files:
        print("ℹ️  Nessun file modificato nell'ultimo commit")
        return
    
    print(f"📝 Trovati {len(changed_files)} file modificati:")
    
    # Inizializza tracker
    tracker = ChangeTracker(CONFIG["tracking_db"])
    
    # Processa ogni file
    for filepath in changed_files:
        # Determina tipo di modifica
        if not os.path.exists(filepath):
            change_type = "deleted"
        else:
            change_type = "modified"  # TODO: distinguere added vs modified
        
        # Ottiene diff
        diff, added, removed = GitHelper.get_file_diff(filepath, CONFIG["max_diff_lines"])
        
        # Crea oggetto FileChange
        change = FileChange(
            filepath=filepath,
            change_type=change_type,
            author=author,
            timestamp=timestamp,
            commit_hash=commit_hash,
            diff_snippet=diff[:500] if diff else None,  # Limita snippet
            lines_added=added,
            lines_removed=removed
        )
        
        # Aggiunge al tracker
        tracker.add_change(change)
        
        print(f"  ✅ {filepath} (+{added} -{removed})")
    
    print(f"\n💾 Modifiche salvate in {CONFIG['tracking_db']}")
    print(f"💡 Usa 'changelog-tracker commit' per aggiungerle al changelog")

def commit_to_changelog(args):
    """Aggiunge le modifiche tracciate al changelog"""
    
    tracker = ChangeTracker(CONFIG["tracking_db"])
    changes = tracker.get_pending_changes()
    
    if not changes:
        print("ℹ️  Nessuna modifica da committare al changelog")
        return
    
    print(f"📋 Trovate {len(changes)} modifiche da aggiungere\n")
    
    # Chiede informazioni per la entry
    version = args.version or input("Versione (es. 1.2.3 o 'Unreleased'): ").strip()
    date = args.date or datetime.datetime.now().strftime("%Y-%m-%d")
    
    print("\nTag disponibili:", ", ".join(CONFIG["default_tags"]))
    tags_input = args.tags or input("Tag (separati da spazio): ").strip()
    tags = tags_input.split() if tags_input else CONFIG["default_tags"]
    
    description = args.description or input("Descrizione (opzionale): ").strip()
    
    # GitHub repo
    github_repo = args.github_repo or CONFIG.get("github_repo") or GitHelper.get_repo_url()
    
    # Crea update
    update = ChangelogUpdate(
        version=version,
        date=date,
        changes=changes,
        tags=tags,
        description=description
    )
    
    # Aggiorna changelog
    changelog = ChangelogManager(CONFIG["changelog_file"])
    changelog.add_entry(update, github_repo)
    
    # Pulisce le modifiche tracciate
    tracker.clear_changes()
    
    print(f"\n✨ Changelog aggiornato con successo!")

def add_pr_to_changelog(args):
    """Aggiunge una PR al changelog con informazioni complete"""
    
    if not args.pr_number:
        print("❌ Devi specificare il numero della PR con --pr-number")
        return
    
    github_repo = args.github_repo or CONFIG.get("github_repo") or GitHelper.get_repo_url()
    
    if not github_repo:
        print("❌ Repository GitHub non configurato!")
        return
    
    # Informazioni PR
    pr_info = {
        "number": args.pr_number,
        "url": f"https://github.com/{github_repo}/pull/{args.pr_number}",
        "author": args.pr_author or "contributor"
    }
    
    # Traccia modifiche se non già fatto
    tracker = ChangeTracker(CONFIG["tracking_db"])
    changes = tracker.get_pending_changes()
    
    if not changes:
        print("⚠️  Nessuna modifica tracciata. Traccio le modifiche correnti...")
        track_changes(args)
        changes = tracker.get_pending_changes()
    
    # Crea entry
    version = args.version or f"PR-{args.pr_number}"
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    tags = args.tags.split() if args.tags else ["#CHANGED"]
    
    update = ChangelogUpdate(
        version=version,
        date=date,
        changes=changes,
        tags=tags,
        description=args.description or f"Modifiche dalla Pull Request #{args.pr_number}",
        pr_info=pr_info
    )
    
    # Aggiorna changelog
    changelog = ChangelogManager(CONFIG["changelog_file"])
    changelog.add_entry(update, github_repo)
    
    tracker.clear_changes()
    
    print(f"\n✨ Pull Request #{args.pr_number} aggiunta al changelog!")

def show_status(args):
    """Mostra lo stato corrente del tracking"""
    
    tracker = ChangeTracker(CONFIG["tracking_db"])
    changes = tracker.get_pending_changes()
    
    print("📊 Status Changelog Tracker\n")
    print(f"Repository: {GitHelper.get_repo_url() or 'N/A'}")
    print(f"Branch: {GitHelper.get_current_branch()}")
    print(f"Changelog file: {CONFIG['changelog_file']}")
    print(f"Tracking DB: {CONFIG['tracking_db']}\n")
    
    if changes:
        print(f"📋 {len(changes)} modifiche in attesa di essere committate:\n")
        for i, change in enumerate(changes, 1):
            print(f"{i}. {change.filepath} ({change.change_type})")
            print(f"   Autore: {change.author}")
            print(f"   Data: {change.timestamp[:19]}")
            if change.lines_added or change.lines_removed:
                print(f"   Modifiche: +{change.lines_added} -{change.lines_removed}\n")
    else:
        print("✅ Nessuna modifica in attesa")

def main():
    parser = argparse.ArgumentParser(
        description="Sistema automatico di tracking changelog con integrazione GitHub"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Comandi disponibili')
    
    # Comando: track
    track_parser = subparsers.add_parser('track', help='Traccia le modifiche correnti')
    track_parser.add_argument('--github-repo', help='Repository GitHub (username/repo)')
    
    # Comando: commit
    commit_parser = subparsers.add_parser('commit', help='Committa modifiche al changelog')
    commit_parser.add_argument('--version', help='Versione (es. 1.2.3)')
    commit_parser.add_argument('--date', help='Data (YYYY-MM-DD)')
    commit_parser.add_argument('--tags', help='Tag separati da spazio')
    commit_parser.add_argument('--description', help='Descrizione')
    commit_parser.add_argument('--github-repo', help='Repository GitHub')
    
    # Comando: add-pr
    pr_parser = subparsers.add_parser('add-pr', help='Aggiunge una PR al changelog')
    pr_parser.add_argument('--pr-number', type=int, required=True, help='Numero PR')
    pr_parser.add_argument('--pr-author', help='Autore della PR')
    pr_parser.add_argument('--version', help='Versione')
    pr_parser.add_argument('--tags', help='Tag separati da spazio')
    pr_parser.add_argument('--description', help='Descrizione')
    pr_parser.add_argument('--github-repo', help='Repository GitHub')
    
    # Comando: status
    status_parser = subparsers.add_parser('status', help='Mostra status corrente')
    
    # Comando: shell
    shell_parser = subparsers.add_parser('shell', help='Avvia shell interattiva')
    
    args = parser.parse_args()
    
    # Se nessun comando, avvia shell interattiva
    if not args.command:
        print(yellow("Nessun comando specificato. Avvio shell interattiva...\n"))
        shell = ChangelogShell()
        shell.run()
        return
    
    # Esegue il comando
    if args.command == 'track':
        track_changes(args)
    elif args.command == 'commit':
        commit_to_changelog(args)
    elif args.command == 'add-pr':
        add_pr_to_changelog(args)
    elif args.command == 'status':
        show_status(args)
    elif args.command == 'shell':
        try:
            shell = ChangelogShell()
            shell.run()
        except Exception as e:
            print(f"Errore nell'avvio della shell: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()