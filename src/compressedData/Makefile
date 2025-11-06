# ============================================================================
# MAKEFILE - Sistema Compressione/Crittografia Avanzato
# ============================================================================

CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -O3 -march=native -flto
LDFLAGS = -lm -lpthread
TARGET = scx

# Directories
SRC_DIR = .
CORE_DIR = core
CHUNK_DIR = chunking
PREPROC_DIR = preprocessing
PRED_DIR = prediction
OBFUSC_DIR = obfuscation
BUILD_DIR = build
BIN_DIR = bin

# Source files
CORE_SRC = $(CORE_DIR)/types.c
CHUNK_SRC = $(CHUNK_DIR)/chunker.c
PREPROC_SRC = $(PREPROC_DIR)/bwt_mtf_rle.c
PRED_SRC = $(PRED_DIR)/predictor.c
OBFUSC_SRC = $(OBFUSC_DIR)/obfuscator.c
MAIN_SRC = main.c

ALL_SRC = $(CORE_SRC) $(CHUNK_SRC) $(PREPROC_SRC) $(PRED_SRC) $(OBFUSC_SRC) $(MAIN_SRC)

# Object files
CORE_OBJ = $(BUILD_DIR)/types.o
CHUNK_OBJ = $(BUILD_DIR)/chunker.o
PREPROC_OBJ = $(BUILD_DIR)/bwt_mtf_rle.o
PRED_OBJ = $(BUILD_DIR)/predictor.o
OBFUSC_OBJ = $(BUILD_DIR)/obfuscator.o
MAIN_OBJ = $(BUILD_DIR)/main.o

ALL_OBJ = $(CORE_OBJ) $(CHUNK_OBJ) $(PREPROC_OBJ) $(PRED_OBJ) $(OBFUSC_OBJ) $(MAIN_OBJ)

# ============================================================================
# TARGETS PRINCIPALI
# ============================================================================

.PHONY: all clean dirs install test help

all: dirs $(BIN_DIR)/$(TARGET)
	@echo "✓ Build completato: $(BIN_DIR)/$(TARGET)"

# Crea directories
dirs:
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)
	@mkdir -p $(CORE_DIR) $(CHUNK_DIR) $(PREPROC_DIR) $(PRED_DIR) $(OBFUSC_DIR)

# Link finale
$(BIN_DIR)/$(TARGET): $(ALL_OBJ)
	@echo "Linking $(TARGET)..."
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@strip $@

# ============================================================================
# COMPILAZIONE MODULI
# ============================================================================

# Core types
$(CORE_OBJ): $(CORE_SRC) $(CORE_DIR)/types.h
	@echo "Compiling core/types.c..."
	$(CC) $(CFLAGS) -c $< -o $@

# Chunking
$(CHUNK_OBJ): $(CHUNK_SRC) $(CORE_DIR)/types.h
	@echo "Compiling chunking/chunker.c..."
	$(CC) $(CFLAGS) -c $< -o $@

# Preprocessing
$(PREPROC_OBJ): $(PREPROC_SRC) $(CORE_DIR)/types.h
	@echo "Compiling preprocessing/bwt_mtf_rle.c..."
	$(CC) $(CFLAGS) -c $< -o $@

# Prediction
$(PRED_OBJ): $(PRED_SRC) $(CORE_DIR)/types.h
	@echo "Compiling prediction/predictor.c..."
	$(CC) $(CFLAGS) -c $< -o $@

# Obfuscation
$(OBFUSC_OBJ): $(OBFUSC_SRC) $(CORE_DIR)/types.h
	@echo "Compiling obfuscation/obfuscator.c..."
	$(CC) $(CFLAGS) -c $< -o $@

# Main
$(MAIN_OBJ): $(MAIN_SRC) $(CORE_DIR)/types.h
	@echo "Compiling main.c..."
	$(CC) $(CFLAGS) -c $< -o $@

# ============================================================================
# BUILD VARIANTS
# ============================================================================

# Debug build
debug: CFLAGS = -Wall -Wextra -std=c11 -O0 -g -DDEBUG
debug: clean all
	@echo "✓ Debug build completato"

# Static build (binario standalone)
static: LDFLAGS += -static
static: clean all
	@echo "✓ Static build completato"

# Release ottimizzato
release: CFLAGS = -Wall -std=c11 -O3 -march=native -flto -DNDEBUG
release: clean all
	@strip -s $(BIN_DIR)/$(TARGET)
	@echo "✓ Release build completato"

# Tiny build (dimensione minima)
tiny: CFLAGS = -Wall -std=c11 -Os -flto -ffunction-sections -fdata-sections
tiny: LDFLAGS += -Wl,--gc-sections
tiny: clean all
	@strip -s $(BIN_DIR)/$(TARGET)
	@upx --best --lzma $(BIN_DIR)/$(TARGET) 2>/dev/null || true
	@ls -lh $(BIN_DIR)/$(TARGET)
	@echo "✓ Tiny build completato"

# Paranoid (massima sicurezza)
paranoid: CFLAGS += -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
paranoid: LDFLAGS += -pie -Wl,-z,relro,-z,now
paranoid: clean all
	@echo "✓ Paranoid build completato"

# ============================================================================
# TESTING
# ============================================================================

test: all
	@echo "=== Running tests ==="
	@echo "Creazione file test..."
	@dd if=/dev/urandom of=test_input.bin bs=1M count=10 2>/dev/null
	@echo ""
	@echo "Test compressione..."
	@time $(BIN_DIR)/$(TARGET) compress test_input.bin test_output.scx
	@echo ""
	@echo "Statistiche file:"
	@ls -lh test_input.bin test_output.scx
	@echo ""
	@echo "✓ Test completato"
	@rm -f test_input.bin test_output.scx

# Test veloce (1MB)
test-fast: all
	@echo "=== Quick test (1MB) ==="
	@dd if=/dev/urandom of=test_1mb.bin bs=1M count=1 2>/dev/null
	@$(BIN_DIR)/$(TARGET) compress test_1mb.bin test_1mb.scx
	@ls -lh test_1mb.bin test_1mb.scx
	@rm -f test_1mb.bin test_1mb.scx

# Benchmark
benchmark: all
	@echo "=== Benchmark ==="
	@echo "Generating test file (100MB)..."
	@dd if=/dev/urandom of=bench.bin bs=1M count=100 2>/dev/null
	@echo ""
	@echo "Compressing..."
	@time -p $(BIN_DIR)/$(TARGET) compress bench.bin bench.scx -q
	@echo ""
	@echo "Results:"
	@ls -lh bench.bin bench.scx
	@rm -f bench.bin bench.scx

# ============================================================================
# STRUTTURA PROGETTO
# ============================================================================

structure:
	@echo "Creazione struttura directory..."
	@mkdir -p $(CORE_DIR) $(CHUNK_DIR) $(PREPROC_DIR) $(PRED_DIR) $(OBFUSC_DIR)
	@mkdir -p $(BUILD_DIR) $(BIN_DIR)
	@touch $(CORE_DIR)/types.h $(CORE_DIR)/types.c
	@touch $(CHUNK_DIR)/chunker.c
	@touch $(PREPROC_DIR)/bwt_mtf_rle.c
	@touch $(PRED_DIR)/predictor.c
	@touch $(OBFUSC_DIR)/obfuscator.c
	@touch main.c
	@echo "✓ Struttura creata"

# ============================================================================
# UTILITIES
# ============================================================================

# Pulizia
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR) $(BIN_DIR)
	@rm -f *.o *.scx test_*.bin bench.bin
	@echo "✓ Clean completato"

# Installazione
install: all
	@echo "Installing to /usr/local/bin..."
	@sudo cp $(BIN_DIR)/$(TARGET) /usr/local/bin/
	@sudo chmod 755 /usr/local/bin/$(TARGET)
	@echo "✓ Installato: /usr/local/bin/$(TARGET)"

# Disinstallazione
uninstall:
	@echo "Removing /usr/local/bin/$(TARGET)..."
	@sudo rm -f /usr/local/bin/$(TARGET)
	@echo "✓ Disinstallato"

# Conta righe codice
loc:
	@echo "Lines of code:"
	@find . -name "*.c" -o -name "*.h" | xargs wc -l | tail -1

# Help
help:
	@echo "Comandi disponibili:"
	@echo "  make              - Build normale"
	@echo "  make debug        - Build con debug symbols"
	@echo "  make release      - Build ottimizzato per release"
	@echo "  make static       - Build statico (no dipendenze)"
	@echo "  make tiny         - Build dimensione minima"
	@echo "  make paranoid     - Build con protezioni massime"
	@echo ""
	@echo "  make test         - Esegui test (10MB)"
	@echo "  make test-fast    - Test veloce (1MB)"
	@echo "  make benchmark    - Benchmark (100MB)"
	@echo ""
	@echo "  make clean        - Pulisci build"
	@echo "  make install      - Installa in /usr/local/bin"
	@echo "  make uninstall    - Rimuovi da /usr/local/bin"
	@echo "  make loc          - Conta righe di codice"
	@echo ""
	@echo "  make structure    - Crea struttura directory"

# ============================================================================
# INFORMAZIONI
# ============================================================================

info:
	@echo "=== Project Info ==="
	@echo "Compiler: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "LDFLAGS: $(LDFLAGS)"
	@echo "Target: $(TARGET)"
	@echo ""
	@echo "Moduli:"
	@echo "  - Core types (types.c/h)"
	@echo "  - Chunking (16MB chunks)"
	@echo "  - Preprocessing (BWT+MTF+RLE)"
	@echo "  - Prediction (Context+Delta)"
	@echo "  - Obfuscation (Poly+Fake+Shuffle)"
	@echo "  - Encryption (AES-256-GCM) [TODO]"

# ============================================================================
# DOCKER BUILD (opzionale)
# ============================================================================

docker-build:
	@echo "Building in Docker..."
	@docker build -t scx-builder .
	@docker run --rm -v $(PWD):/build scx-builder
	@echo "✓ Docker build completato"

# ============================================================================
# GENERAZIONE DOCUMENTAZIONE
# ============================================================================

docs:
	@echo "Generando documentazione..."
	@doxygen Doxyfile 2>/dev/null || echo "Doxygen non installato"
	@echo "✓ Documentazione in docs/"

# ============================================================================
# PROFILING
# ============================================================================

profile: CFLAGS += -pg
profile: clean all
	@echo "Build con profiling abilitato"
	@echo "Esegui il programma e poi usa: gprof $(BIN_DIR)/$(TARGET) gmon.out"

# ============================================================================
# VALGRIND CHECK
# ============================================================================

valgrind: debug
	@echo "=== Valgrind Memory Check ==="
	@dd if=/dev/zero of=test_val.bin bs=1M count=1 2>/dev/null
	@valgrind --leak-check=full --show-leak-kinds=all \
		$(BIN_DIR)/$(TARGET) compress test_val.bin test_val.scx
	@rm -f test_val.bin test_val.scx

# ============================================================================
# GIT HELPERS
# ============================================================================

git-init:
	@git init
	@echo "build/" >> .gitignore
	@echo "bin/" >> .gitignore
	@echo "*.o" >> .gitignore
	@echo "*.scx" >> .gitignore
	@echo "test_*" >> .gitignore
	@echo "bench.*" >> .gitignore
	@git add .
	@echo "✓ Git repository inizializzato"

# ============================================================================
# DEFAULT
# ============================================================================

.DEFAULT_GOAL := all