import hashlib

def calcola_hash_file(percorso_file, algoritmo="sha256"):
    try:
        hasher = hashlib.new(algoritmo)
        
        with open(percorso_file, "rb") as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    except FileNotFoundError:
        return f"Errore: Il file '{percorso_file}' non è stato trovato."
    except ValueError:
        return f"Errore: Algoritmo di hashing '{algoritmo}' non valido."

nome_file = "bootstrap_manager.cpp" 
hash_sha256 = calcola_hash_file(nome_file, "sha256")
hash_md5 = calcola_hash_file(nome_file, "md5")

print(f"Hash SHA-256 di {nome_file}: {hash_sha256}")
print(f"Hash MD5 di {nome_file}: {hash_md5}")
