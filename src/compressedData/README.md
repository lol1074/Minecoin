# SCX - Secure Compressed eXecutable

Sistema avanzato di compressione e crittografia con pipeline multi-stage.

## Features

- **Chunking**: File divisi in chunk da 16MB
- **Pre-processing**: BWT + MTF + RLE
- **Prediction**: Context modeling + Delta encoding
- **Obfuscation**: Polymorphic + Fake data + Structure shuffle
- **Encryption**: AES-256-GCM + Argon2id (TODO)

## Build

```bash
# Setup e build
./setup.sh

# Build normale
make

# Build ottimizzato
make release

# Build debug
make debug
```

## Usage

```bash
# Comprimi file
./bin/scx compress input.bin output.scx

# Decomprimi file
./bin/scx decompress input.scx output.bin

# Con password
./bin/scx compress file.bin file.scx -p mypassword

# Verbose
./bin/scx compress file.bin file.scx -v
```

## Test

```bash
# Test veloce (1MB)
make test-fast

# Test normale (10MB)
make test

# Benchmark (100MB)
make benchmark
```

## Architecture

```
INPUT → Chunking → Pre-processing → Prediction → Obfuscation → Encryption → OUTPUT
```

## License

MIT License
