#ifndef CORE_TYPES_H
#define CORE_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>  // necessario per FILE*

// === Costanti globali ===
#define CHUNK_SIZE       (16 * 1024 * 1024)
#define MAX_CHUNKS       4096
#define IV_SIZE          12
#define TAG_SIZE         16
#define SALT_SIZE        32
#define KEY_SIZE         32
#define HMAC_SIZE        64
#define LZ4_DICT_SIZE    (64 * 1024)   // 64KB dictionary
#define HUFFMAN_MAX_BITS 15
#define ANS_TABLE_SIZE   4096

#define ARGON2_MEMORY      (1024 * 1024)
#define ARGON2_ITERATIONS  10
#define ARGON2_PARALLELISM 8

// === Enum ===

typedef enum {
    CIPHER_AES_256_GCM = 0,
    CIPHER_CHACHA20_POLY1305 = 1
} CipherType;

typedef enum {
    COMP_NONE = 0,
    COMP_LZ4 = 1,
    COMP_HUFFMAN = 2,
    COMP_ANS = 3,
    COMP_ALL = 4
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

// === Struct base ===

typedef struct {
    uint8_t *data;
    size_t size;
    size_t capacity;
    bool owns_memory;
} Buffer;

typedef struct {
    uint32_t index;
    uint32_t original_size;
    uint32_t compressed_size;
    uint32_t encrypted_size;
    uint8_t iv[IV_SIZE];
    uint8_t tag[TAG_SIZE];
    uint8_t *data;
    uint32_t checksum;
} Chunk;

typedef struct {
    char original_name[256];
    uint64_t timestamp;
    uint32_t attributes;
    uint32_t metadata_size;
    uint8_t *metadata;  // opzionale
} FileMetadata;

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t cipher_type;
    uint32_t chunk_count;
    uint64_t total_size;
    uint8_t salt[SALT_SIZE];
    uint32_t flags;
    uint8_t reserved[32];
} FileHeader;

typedef struct {
    CipherType cipher;
    uint8_t master_key[KEY_SIZE];
    uint8_t hmac_key[KEY_SIZE];
    void *cipher_ctx; // Context OpenSSL o altra crypto lib
} EncryptionContext;

typedef struct {
    CompressionType type;
    void *state;               // Stato specifico dell’algoritmo
    uint8_t dict[LZ4_DICT_SIZE];
    size_t dict_size;
} CompressionContext;

typedef struct {
    ObfuscationType type;
    uint32_t seed;
    size_t fake_data_percent;
    bool shuffle_chunks;
} ObfuscationContext;

// === Strutture di processo ===

typedef struct {
    FILE *input_file;
    uint64_t file_size;
    uint32_t total_chunks;
    uint32_t current_chunk;
    size_t chunk_size;
    bool eof_reached;
} ChunkReader;

typedef struct {
    FILE *output_file;
    uint32_t chunks_written;
    uint64_t bytes_written;
} ChunkWriter;

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

    // Callback di progresso
    void (*progress_callback)(float percent, void *user_data);
    void *progress_user_data;

    // Statistiche
    uint64_t bytes_processed;
    uint64_t bytes_written;
    double compression_ratio;
    double time_elapsed;
} ProcessContext;

typedef struct {
    uint32_t *fake_positions;  // Posizioni fake data
    uint32_t fake_count;
    uint32_t real_size;
} FakeDataMap;

typedef struct {
    uint32_t *permutation;  // Array permutazione
    uint32_t block_count;
    uint32_t block_size;
} ShuffleMap;


typedef struct {
    uint8_t *data;
    uint32_t size;
    
    // Metadata per deobfuscation
    uint32_t poly_seed;
    bool used_polymorphic;
    
    FakeDataMap *fake_map;
    bool used_fake_data;
    
    ShuffleMap *shuffle_map;
    bool used_shuffle;
    
    uint32_t original_size;
} ObfuscationResult;

// === Altri risultati/intermedi ===

typedef struct {
    uint8_t *data;
    uint32_t size;
    uint32_t bwt_primary_index;
    bool used_bwt;
    bool used_mtf;
    bool used_rle;
} PreprocessResult;

typedef struct {
    uint8_t *data;
    uint32_t size;
    int stride;
    bool used_context;
    bool used_delta;
} PredictionResult;

// === Funzioni core ===

// Buffer
Buffer* buffer_create(size_t capacity);
void buffer_free(Buffer *buf);
bool buffer_append(Buffer *buf, const void *data, size_t size);
void buffer_clear_secure(Buffer *buf);

// Chunk
Chunk* chunk_create(uint32_t index);
void chunk_free(Chunk *chunk);

// Utilità
void generate_iv(uint8_t *iv, size_t size);
void secure_zero(void *ptr, size_t size);
uint32_t fast_checksum(const uint8_t *data, size_t size);
const char* status_to_string(StatusCode status);
void print_error(StatusCode status, const char *context);
double get_time(void);
double analyze_entropy(const uint8_t *data, uint32_t size);
void generate_salt(uint8_t *salt, size_t size);

// Gestione contesto
ProcessContext* context_create(void);
void context_free(ProcessContext *ctx);
void context_reset(ProcessContext *ctx);

#endif // CORE_TYPES_H
