#ifndef CORE_TYPES_H
#define CORE_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// ============================================================================
// CONFIGURAZIONE SISTEMA
// ============================================================================

#define CHUNK_SIZE (16 * 1024 * 1024)  // 16MB chunks
#define MAX_CHUNKS 4096                 // Max 64GB file
#define IV_SIZE 12                      // 96-bit IV per GCM
#define TAG_SIZE 16                     // 128-bit auth tag
#define SALT_SIZE 32                    // 256-bit salt
#define KEY_SIZE 32                     // 256-bit key
#define HMAC_SIZE 64                    // 512-bit HMAC

// Argon2id parameters
#define ARGON2_MEMORY (1024 * 1024)     // 1GB in KB
#define ARGON2_ITERATIONS 10
#define ARGON2_PARALLELISM 8

// Compression parameters
#define LZ4_DICT_SIZE (64 * 1024)       // 64KB dictionary
#define HUFFMAN_MAX_BITS 15
#define ANS_TABLE_SIZE 4096

// ============================================================================
// ENUMERAZIONI
// ============================================================================

typedef enum {
    CIPHER_AES_256_GCM = 0,
    CIPHER_CHACHA20_POLY1305 = 1
} CipherType;

typedef enum {
    COMP_NONE = 0,
    COMP_LZ4 = 1,
    COMP_HUFFMAN = 2,
    COMP_ANS = 3,
    COMP_ALL = 4  // LZ4 + Huffman + ANS
} CompressionType;

typedef enum {
    STATUS_OK = 0,
    STATUS_ERROR_IO = 1,
    STATUS_ERROR_MEMORY = 2,
    STATUS_ERROR_CRYPTO = 3,
    STATUS_ERROR_COMPRESSION = 4,
    STATUS_ERROR_INTEGRITY = 5,
    STATUS_ERROR_PASSWORD = 6,
    STATUS_ERROR_FORMAT = 7
} StatusCode;

typedef enum {
    OBFUSCATE_NONE = 0,
    OBFUSCATE_POLYMORPHIC = 1,
    OBFUSCATE_FAKE_DATA = 2,
    OBFUSCATE_STRUCTURE = 4,
    OBFUSCATE_ALL = 7
} ObfuscationType;

// ============================================================================
// STRUTTURE DATI
// ============================================================================

// Buffer generico con gestione memoria
typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
    bool owns_memory;  // true se deve fare free
} Buffer;

// Chunk di dati (16MB)
typedef struct {
    uint32_t index;           // Indice chunk
    uint32_t original_size;   // Dimensione originale
    uint32_t compressed_size; // Dopo compressione
    uint32_t encrypted_size;  // Dopo encryption
    uint8_t iv[IV_SIZE];      // IV unico per chunk
    uint8_t tag[TAG_SIZE];    // Auth tag
    uint8_t *data;            // Dati processati
    uint32_t checksum;        // Checksum pre-encryption
} Chunk;

// Header file compresso (encrypted)
typedef struct {
    uint32_t magic;           // Magic number (obfuscated)
    uint16_t version;         // Versione formato
    uint16_t cipher_type;     // Tipo cifrario
    uint32_t chunk_count;     // Numero chunks
    uint64_t total_size;      // Dimensione totale originale
    uint8_t salt[SALT_SIZE];  // Salt per key derivation
    uint32_t flags;           // Feature flags
    uint8_t reserved[32];     // Riservato futuro
} FileHeader;

// Metadati file (encrypted separatamente)
typedef struct {
    char original_name[256];  // Nome file originale
    uint64_t timestamp;       // Unix timestamp
    uint32_t attributes;      // Attributi file
    uint32_t metadata_size;   // Dimensione metadata custom
    uint8_t *metadata;        // Metadata custom opzionale
} FileMetadata;

// Contesto compressione
typedef struct {
    CompressionType type;
    void *state;              // State specifico algoritmo
    uint8_t dict[LZ4_DICT_SIZE]; // Dictionary LZ4
    size_t dict_size;
} CompressionContext;

// Contesto encryption
typedef struct {
    CipherType cipher;
    uint8_t master_key[KEY_SIZE];
    uint8_t hmac_key[KEY_SIZE];
    void *cipher_ctx;         // Context OpenSSL/crypto lib
} EncryptionContext;

// Contesto obfuscation
typedef struct {
    ObfuscationType type;
    uint32_t seed;            // Seed per randomizzazione
    size_t fake_data_percent; // % di fake data da iniettare
    bool shuffle_chunks;      // Shuffle ordine chunks
} ObfuscationContext;

// Contesto completo operazione
typedef struct {
    FileHeader header;
    FileMetadata metadata;
    
    CompressionContext compression;
    EncryptionContext encryption;
    ObfuscationContext obfuscation;
    
    Chunk *chunks;
    uint32_t chunk_count;
    
    char password[256];
    bool use_password;
    
    // Callbacks progress
    void (*progress_callback)(float percent, void *user_data);
    void *progress_user_data;
    
    // Statistics
    uint64_t bytes_processed;
    uint64_t bytes_written;
    double compression_ratio;
    double time_elapsed;
} ProcessContext;

// Statistiche elaborate
typedef struct {
    uint64_t original_size;
    uint64_t compressed_size;
    uint64_t encrypted_size;
    double compression_ratio;
    double encryption_overhead;
    double total_time;
    double compression_time;
    double encryption_time;
    double io_time;
} ProcessStats;

// ============================================================================
// FUNZIONI BUFFER
// ============================================================================

// Crea buffer con capacità iniziale
Buffer* buffer_create(size_t capacity);

// Libera buffer
void buffer_free(Buffer *buf);

// Appende dati a buffer (auto-resize)
bool buffer_append(Buffer *buf, const void *data, size_t size);

// Pulisce buffer (azzera dati sensibili)
void buffer_clear_secure(Buffer *buf);

// Ridimensiona buffer
bool buffer_resize(Buffer *buf, size_t new_size);

// ============================================================================
// FUNZIONI CHUNK
// ============================================================================

// Crea chunk vuoto
Chunk* chunk_create(uint32_t index);

// Libera chunk
void chunk_free(Chunk *chunk);

// Alloca dati chunk
bool chunk_allocate(Chunk *chunk, size_t size);

// ============================================================================
// FUNZIONI CONTEXT
// ============================================================================

// Inizializza context
ProcessContext* context_create(void);

// Libera context (secure wipe)
void context_free(ProcessContext *ctx);

// Reset context per nuovo file
void context_reset(ProcessContext *ctx);

// ============================================================================
// UTILITY
// ============================================================================

// Genera IV random (crypto-safe)
void generate_iv(uint8_t *iv, size_t size);

// Genera salt random
void generate_salt(uint8_t *salt, size_t size);

// Secure memory wipe (anti-compiler optimization)
void secure_zero(void *ptr, size_t size);

// Calcola checksum veloce (non crypto)
uint32_t fast_checksum(const uint8_t *data, size_t size);

// ============================================================================
// ERROR HANDLING
// ============================================================================

// Converte status code a stringa
const char* status_to_string(StatusCode status);

// Stampa errore con context
void print_error(StatusCode status, const char *context);

#endif // CORE_TYPES_H