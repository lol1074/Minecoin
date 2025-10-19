import os
import json
import curses
import subprocess
from datetime import datetime
from git import Repo, InvalidGitRepositoryError  # GitPython


DATA_FILE = 'changelog.json'
VALID_TOPIC_PREFIX = '#'  # tutti i topic devono iniziare con '#'
# mega topic = es: #fix, #security
# macro topic = es: #fix/db , #security/encryption

def validate_topics(topics):
    """Verifica che ogni topic rispetti la struttura: inizia con '#', e se contiene '/', la parte prima è mega topic."""
    valid = []
    for t in topics:
        t = t.strip()
        if not t:
            continue
        if not t.startswith(VALID_TOPIC_PREFIX):
            raise ValueError(f"Invalid topic '{t}': must start with '{VALID_TOPIC_PREFIX}'")
        # se contiene slash, controlla che la parte prima non abbia slash
        parts = t[1:].split('/')  # skip '#'
        if len(parts) > 1:
            mega = parts[0]
            if '/' in mega:
                raise ValueError(f"Invalid topic '{t}': mega topic contains slash")
        valid.append(t)
    return valid

def export_to_markdown(changes, out_file='CHANGELOG.md'):
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write("# Changelog\n\n")
        for c in changes:
            topics = ", ".join(c['topics'])
            f.write(f"## {c['date']} — {c['author']}\n")
            f.write(f"- **Descrizione**: {c['description']}\n")
            f.write(f"- **Topics**: {topics}\n")
            if c.get('link'):
                f.write(f"- **Link al codice**: {c['link']}\n")
            f.write("\n")
    print(f"[+] - Esportato in Markdown: {out_file}")

def export_to_html(changes, out_file='CHANGELOG.html'):
    with open(out_file, 'w', encoding='utf-8') as f:
        f.write("<!DOCTYPE html>\n<html lang=\"en\">\n<head><meta charset=\"UTF-8\"><title>Changelog</title></head>\n<body>\n")
        f.write("<h1>Changelog</h1>\n")
        for c in changes:
            topics = ", ".join(c['topics'])
            f.write(f"<h2>{c['date']} — {c['author']}</h2>\n")
            f.write("<ul>\n")
            f.write(f"<li><strong>Descrizione</strong>: {c['description']}</li>\n")
            f.write(f"<li><strong>Topics</strong>: {topics}</li>\n")
            if c.get('link'):
                f.write(f"<li><strong>Link al codice</strong>: <a href=\"{c['link']}\">{c['link']}</a></li>\n")
            f.write("</ul>\n")
        f.write("</body>\n</html>\n")
    print(f"[+] - Esportato in HTML: {out_file}")

def find_latest_commit_link(repo_path='.'):
    try:
        repo = Repo(repo_path, search_parent_directories=True)
        commit = repo.head.commit
        # qui generiamo un link simbolico: hash
        return commit.hexsha
    except InvalidGitRepositoryError:
        return None

class Changelog:
    def __init__(self, data_file=DATA_FILE):
        self.data_file = data_file
        self.changes = self.load_changes()

    def load_changes(self):
        if not os.path.exists(self.data_file):
            return []
        with open(self.data_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    def save_changes(self):
        with open(self.data_file, 'w', encoding='utf-8') as f:
            json.dump(self.changes, f, indent=4, ensure_ascii=False)

    def add_change(self, change):
        self.changes.append(change)
        self.save_changes()

    def list_changes(self):
        return self.changes

    def print_changes(self):
        if not self.changes:
            print("Nessun changelog presente.")
            return
        for idx, change in enumerate(self.changes, 1):
            print(f"{idx}. {change['date']} - {change['author']}: {change['description']}")
            print(f"    Topics: {', '.join(change['topics'])}")
            print(f"    Link: {change.get('link','')}")
            print("-" * 60)

    def filter_by_keyword(self, keyword):
        return [c for c in self.changes if keyword.lower() in c['description'].lower()]

    def filter_by_author(self, author):
        return [c for c in self.changes if author.lower() in c['author'].lower()]

    def add_topic(self, idx, topic):
        if 0 <= idx < len(self.changes):
            # valida topic
            topic_valid = validate_topics([topic])[0]
            self.changes[idx]['topics'].append(topic_valid)
            self.save_changes()
            return True
        return False

def editor(stdscr, changelog: Changelog):
    curses.curs_set(1)
    stdscr.clear()
    changes = changelog.list_changes()
    if not changes:
        stdscr.addstr(0, 0, "Nessun changelog da modificare. Premere ESC per uscire.")
        stdscr.refresh()
        stdscr.getch()
        return

    current_line = 0
    mode = 'NORMAL'  # NORMAL or INSERT
    input_buffer = ''

    while True:
        stdscr.clear()
        max_y, max_x = stdscr.getmaxyx()
        header = f"-- MODE: {mode} -- (j/k = giù/su, i = inserisci, q = esci)"
        stdscr.addstr(0, 0, header)

        # visualizza le righe
        for idx, change in enumerate(changes):
            line = f"{idx+1}. {change['date']} - {change['author']}: {change['description']}"
            if idx == current_line:
                stdscr.addstr(idx+1, 0, line[:max_x-1], curses.A_REVERSE)
            else:
                stdscr.addstr(idx+1, 0, line[:max_x-1])

        stdscr.refresh()
        key = stdscr.getch()

        if mode == 'NORMAL':
            if key == ord('j'):
                current_line = min(len(changes)-1, current_line+1)
            elif key == ord('k'):
                current_line = max(0, current_line-1)
            elif key == ord('i'):
                # entra in modalità inserimento
                mode = 'INSERT'
                input_buffer = changes[current_line]['description']  # pre­popola con vecchia descrizione
                # posizionamento cursor
                stdscr.move(current_line+1, 0)
            elif key == ord('q'):
                break
        elif mode == 'INSERT':
            stdscr.addstr(max_y-1, 0, "INSERISCI descrizione (ESC per uscire insert e salvare): ")
            stdscr.refresh()
            if key == 27:  # ESC
                
                changes[current_line]['description'] = input_buffer
                changelog.save_changes()
                mode = 'NORMAL'
            elif key in (curses.KEY_BACKSPACE, 127):
                input_buffer = input_buffer[:-1]
            elif key == 10:  # ENTER
                input_buffer += '\n'
            elif 32 <= key < 127:
                input_buffer += chr(key)
            # aggiorna la descrizione visualizzata immediatamente
            changes[current_line]['description'] = input_buffer

def interactive_shell():
    changelog = Changelog()

    while True:
        print("\n--- Changelog Tool ---")
        print("1. Aggiungi changelog")
        print("2. Elenca changelog")
        print("3. Filtra per keyword")
        print("4. Filtra per autore")
        print("5. Aggiungi topic")
        print("6. Editor stile Vim‑avanzato")
        print("7. Esporta Markdown")
        print("8. Esporta HTML")
        print("9. Esci")

        choice = input("Scegli un’opzione: ").strip()

        if choice == '1':
            now = datetime.now().strftime("%Y-%m-%d %H:%M")
            author = input("Autore: ").strip()
            description = input("Descrizione: ").strip()
            topics_input = input("Topic (es. #fix, #feature/db): ").strip()
            topics = [t.strip() for t in topics_input.split(',')]
            try:
                topics = validate_topics(topics)
            except ValueError as e:
                print(f"[-] - Errore topics: {e}")
                continue
            link = find_latest_commit_link() or input("Link al codice (vuoto per nessuno): ").strip()
            change = {
                "date": now,
                "author": author,
                "description": description,
                "topics": topics,
                "link": link
            }
            changelog.add_change(change)
            print("[+] - Changelog aggiunto.")

        elif choice == '2':
            changelog.print_changes()

        elif choice == '3':
            keyword = input("Parola chiave: ").strip()
            results = changelog.filter_by_keyword(keyword)
            if results:
                for c in results:
                    print(f"{c['date']} - {c['author']}: {c['description']} [{', '.join(c['topics'])}] Link: {c.get('link','')}")
            else:
                print("[-] - Nessun risultato trovato.")

        elif choice == '4':
            author = input("Autore: ").strip()
            results = changelog.filter_by_author(author)
            if results:
                for c in results:
                    print(f"{c['date']} - {c['author']}: {c['description']} [{', '.join(c['topics'])}] Link: {c.get('link','')}")
            else:
                print("[-] - Nessun risultato trovato.")

        elif choice == '5':
            changelog.print_changes()
            try:
                idx = int(input("Numero changelog: ")) - 1
                topic = input("Nuovo topic: ").strip()
                if changelog.add_topic(idx, topic):
                    print("[+] - Topic aggiunto.")
                else:
                    print("[-] - Indice non valido.")
            except ValueError:
                print("[-] - Input non valido.")

        elif choice == '6':
            curses.wrapper(editor, changelog)

        elif choice == '7':
            export_to_markdown(changelog.list_changes())

        elif choice == '8':
            export_to_html(changelog.list_changes())

        elif choice == '9':
            print("Uscita…")
            break

        else:
            print("[-] - Comando non valido.")

# === MAIN ===
if __name__ == '__main__':
    interactive_shell()
