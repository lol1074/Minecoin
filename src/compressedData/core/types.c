#define _POSIX_C_SOURCE 199309L
#include "types.h"
#include "time.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <wincrypt.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

Buffer *buffer_create(size_t capacity) {
  Buffer *buf = calloc(1, sizeof(Buffer));
  if (!buf)
    return NULL;

  if (capacity > 0) {
    buf->data = malloc(capacity);
    if (!buf->data) {
      free(buf);
      return NULL;
    }
    buf->capacity = capacity;
  }

  buf->size = 0;
  buf->owns_memory = true;

  return buf;
}

void buffer_free(Buffer *buf) {
  if (!buf)
    return;

  if (buf->owns_memory && buf->data) {
    secure_zero(buf->data, buf->capacity);
    free(buf->data);
  }

  secure_zero(buf, sizeof(Buffer));
  free(buf);
}

bool buffer_append(Buffer *buf, const void *data, size_t size) {
  if (!buf || !data || size == 0)
    return false;

  // Auto-resize se necessario
  if (buf->size + size > buf->capacity) {
    size_t new_capacity = (buf->size + size) * 2;
    uint8_t *new_data = realloc(buf->data, new_capacity);

    if (!new_data)
      return false;

    buf->data = new_data;
    buf->capacity = new_capacity;
  }

  memcpy(buf->data + buf->size, data, size);
  buf->size += size;

  return true;
}

void buffer_clear_secure(Buffer *buf) {
  if (!buf)
    return;

  if (buf->data && buf->size > 0) {
    secure_zero(buf->data, buf->size);
  }
  buf->size = 0;
}

bool buffer_resize(Buffer *buf, size_t new_size) {
  if (!buf)
    return false;

  if (new_size > buf->capacity) {
    uint8_t *new_data = realloc(buf->data, new_size);
    if (!new_data)
      return false;

    buf->data = new_data;
    buf->capacity = new_size;
  }

  buf->size = new_size;
  return true;
}

Chunk *chunk_create(uint32_t index) {
  Chunk *chunk = calloc(1, sizeof(Chunk));
  if (!chunk)
    return NULL;

  chunk->index = index;
  chunk->original_size = 0;
  chunk->compressed_size = 0;
  chunk->encrypted_size = 0;
  chunk->data = NULL;

  generate_iv(chunk->iv, IV_SIZE);

  return chunk;
}

void chunk_free(Chunk *chunk) {
  if (!chunk)
    return;

  if (chunk->data) {
    secure_zero(chunk->data, chunk->encrypted_size);
    free(chunk->data);
  }

  secure_zero(chunk, sizeof(Chunk));
}

bool chunk_allocate(Chunk *chunk, size_t size) {
  if (!chunk)
    return false;

  if (chunk->data) {
    secure_zero(chunk->data, chunk->encrypted_size);
    free(chunk->data);
  }

  chunk->data = malloc(size);
  if (!chunk->data)
    return false;

  chunk->encrypted_size = size;
  return true;
}

ProcessContext *context_create(void) {
  ProcessContext *ctx = calloc(1, sizeof(ProcessContext));
  if (!ctx)
    return NULL;

  // Inizializza header con defaults
  ctx->header.magic = 0x53435846; // "SCXF" obfuscated
  ctx->header.version = 0x0100;
  ctx->header.cipher_type = CIPHER_AES_256_GCM;
  ctx->header.flags = 0;

  // Genera salt per key derivation
  generate_salt(ctx->header.salt, SALT_SIZE);

  // Defaults compression
  ctx->compression.type = COMP_ALL;
  ctx->compression.dict_size = 0;

  // Defaults obfuscation
  ctx->obfuscation.type = OBFUSCATE_ALL;
  ctx->obfuscation.seed = (uint32_t)time(NULL);
  ctx->obfuscation.fake_data_percent = 5; // 5% fake data
  ctx->obfuscation.shuffle_chunks = true;

  // Defaults encryption
  ctx->encryption.cipher = CIPHER_AES_256_GCM;

  ctx->use_password = false;
  ctx->chunk_count = 0;
  ctx->chunks = NULL;

  return ctx;
}

void context_free(ProcessContext *ctx) {
  if (!ctx)
    return;

  // Pulisci chunks
  if (ctx->chunks) {
    for (uint32_t i = 0; i < ctx->chunk_count; i++) {
      chunk_free(&ctx->chunks[i]);
    }
    free(ctx->chunks);
  }

  if (ctx->metadata.metadata) {
    secure_zero(ctx->metadata.metadata, ctx->metadata.metadata_size);
    free(ctx->metadata.metadata);
  }

  secure_zero(ctx->password, sizeof(ctx->password));
  secure_zero(&ctx->encryption, sizeof(EncryptionContext));

  secure_zero(ctx, sizeof(ProcessContext));
  free(ctx);
}

void context_reset(ProcessContext *ctx) {
  if (!ctx)
    return;

  if (ctx->chunks) {
    for (uint32_t i = 0; i < ctx->chunk_count; i++) {
      chunk_free(&ctx->chunks[i]);
    }
    free(ctx->chunks);
    ctx->chunks = NULL;
  }

  ctx->chunk_count = 0;
  ctx->bytes_processed = 0;
  ctx->bytes_written = 0;
  ctx->compression_ratio = 0.0;
  ctx->time_elapsed = 0.0;

  generate_salt(ctx->header.salt, SALT_SIZE);

  // Nuovo seed obfuscation
  ctx->obfuscation.seed = (uint32_t)time(NULL);
}

void generate_iv(uint8_t *iv, size_t size) {
  if (!iv || size == 0)
    return;

#ifdef _WIN32
  HCRYPTPROV hProv;
  if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL,
                          CRYPT_VERIFYCONTEXT)) {
    CryptGenRandom(hProv, (DWORD)size, iv);
    CryptReleaseContext(hProv, 0);
  } else {
    srand((unsigned)time(NULL));
    for (size_t i = 0; i < size; i++) {
      iv[i] = (uint8_t)(rand() % 256);
    }
  }
#else
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd >= 0) {
    ssize_t result = read(fd, iv, size);
    close(fd);
    if (result == (ssize_t)size)
      return;
  }

  // Fallback
  srand((unsigned)time(NULL));
  for (size_t i = 0; i < size; i++) {
    iv[i] = (uint8_t)(rand() % 256);
  }
#endif
}

void generate_salt(uint8_t *salt, size_t size) {
  generate_iv(salt, size); // Stesso meccanismo
}

void secure_zero(void *ptr, size_t size) {
  if (!ptr || size == 0)
    return;

  volatile uint8_t *p = (volatile uint8_t *)ptr;
  while (size--) {
    *p++ = 0;
  }

  // Barrier per essere sicuri
  __asm__ __volatile__("" ::: "memory");
}

uint32_t fast_checksum(const uint8_t *data, size_t size) {
  if (!data || size == 0)
    return 0;

  // FNV-1a hash modificato
  uint32_t hash = 0x811C9DC5;

  for (size_t i = 0; i < size; i++) {
    hash ^= data[i];
    hash *= 0x01000193;
    hash = (hash << 13) | (hash >> 19);
  }

  return hash;
}

const char *status_to_string(StatusCode status) {
  switch (status) {
  case STATUS_OK:
    return "OK";
  case STATUS_ERROR_IO:
    return "I/O Error";
  case STATUS_ERROR_MEMORY:
    return "Memory Allocation Error";
  case STATUS_ERROR_CRYPTO:
    return "Cryptographic Error";
  case STATUS_ERROR_COMPRESSION:
    return "Compression Error";
  case STATUS_ERROR_INTEGRITY:
    return "Integrity Check Failed";
  case STATUS_ERROR_PASSWORD:
    return "Invalid Password";
  case STATUS_ERROR_FORMAT:
    return "Invalid File Format";
  default:
    return "Unknown Error";
  }
}

void print_error(StatusCode status, const char *context) {
  fprintf(stderr, "ERROR [%s]: %s\n", context ? context : "Unknown",
          status_to_string(status));
}

#ifdef _WIN32
double get_time(void) {
  static LARGE_INTEGER frequency;
  static bool initialized = false;

  if (!initialized) {
    QueryPerformanceFrequency(&frequency);
    initialized = true;
  }

  LARGE_INTEGER counter;
  QueryPerformanceCounter(&counter);
  return (double)counter.QuadPart / frequency.QuadPart;
}
#else
double get_time(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec + ts.tv_nsec / 1000000000.0;
}
#endif
