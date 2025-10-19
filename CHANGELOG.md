## [Unreleased]
### #FEATURE #ADDED #TODO
- Sistema di ricerca avanzata per changelog (#FEATURE)
- Migliorata la shell interattiva, ora supporta colori e completamento automatico (#ADDED)
- TODO: implementare la sincronizzazione remota dei changelog tra più repo (#TODO)
- Fix minori su parsing changelog (#FIX)
- Testo libero di esempio per testare la ricerca fulltext sul file.  
  Qui puoi scrivere anche descrizioni molto lunghe che superano le 200 righe in totale nel file!

### #DOC
- Aggiornata la documentazione del progetto.
- Aggiunta sezione "Come contribuire".

---

## [2.0.0] - 2025-10-19
### #FEATURE #SECURITY
- Implementato controllo integrità file tramite hash (#FEATURE)
- Migliorata la gestione della sicurezza, ora vengono bloccate operazioni non autorizzate (#SECURITY)

### #FIX
- Risolto bug critico nella funzione di ricerca (#FIX)
- Fix parsing delle date nei changelog
- Fix edge case: parsing di versioni con nomi strani

---

## [1.1.0] - 2025-10-10
### #ADDED #CHANGED
- Aggiunto supporto per i tag personalizzati nei changelog (#ADDED)
- Cambiata la struttura dell’output della shell interattiva (#CHANGED)
- Ora puoi filtrare per data, versione, tag, parola chiave

---

## [1.0.1] - 2025-10-01
### #FIX #REMOVED
- Eliminato codice morto dal parser (#REMOVED)
- Fix minore: ora la ricerca è case-insensitive (#FIX)
- Risolto bug che impediva la ricerca su changelog più lunghi di 100 righe (#FIX)
- Fix su stampa di errori nella shell

---

## [1.0.0] - 2025-09-25
### #FEATURE
- Prima release stabile della CLI changelog search (#FEATURE)
- Supporto a ricerca per parola chiave, versione, data
- Shell interattiva di base

---

## [0.9.0] - 2025-09-10
### #TODO #FIX #DOC
- TODO: aggiungere esportazione risultati ricerca (#TODO)
- Fix vari su parsing dei tag (#FIX)
- Aggiornata la documentazione con esempi di utilizzo (#DOC)
- Questo blocco serve a testare la ricerca di testo su descrizioni molto lunghe, con più di cento righe, per vedere se il parser gestisce tutto correttamente.

Nota di test:
Qui puoi inserire anche
- Blocchi di testo multilinea
- Codice di esempio
```python
print("Hello Changelog!")
```
- Liste numerate
1. Primo punto
2. Secondo punto
- E qualsiasi altro formato tu voglia provare.
---

## [0.8.0]
### #FIX
- Fix iniziale per la shell interattiva (#FIX)
