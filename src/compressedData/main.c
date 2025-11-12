

#include "api.h"
#include "core/types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static bool g_verbose = true;
static bool g_show_progress = true;

// ============================================================================
// PROGRESS CALLBACK
// ============================================================================

static void progress_callback(float percent, const char *stage) {
  if (!g_show_progress)
    return;

  int bar_width = 50;
  int filled = (int)(bar_width * percent / 100.0f);

  printf("\r[");
  for (int i = 0; i < bar_width; i++) {
    if (i < filled)
      printf("=");
    else if (i == filled)
      printf(">");
    else
      printf(" ");
  }
  printf("] %.1f%% - %s", percent, stage);
  fflush(stdout);

  if (percent >= 100.0f) {
    printf("\n");
  }
}

// ============================================================================
// CHUNK PROCESSING PIPELINE
// ============================================================================

typedef struct {
  PreprocessResult *preprocess;
  PredictionResult *prediction;
  ObfuscationResult *obfuscation;
} ChunkPipelineResult;

// Processa singolo chunk attraverso tutta la pipeline
ChunkPipelineResult *process_chunk_compress(Chunk *chunk, ProcessContext *ctx) {
  if (!chunk || !ctx)
    return NULL;

  ChunkPipelineResult *result = calloc(1, sizeof(ChunkPipelineResult));
  if (!result)
    return NULL;

  const uint8_t *current_data = chunk->data;
  uint32_t current_size = chunk->original_size;

  if (g_verbose) {
    printf("\n  Chunk %u: %u bytes\n", chunk->index, current_size);
    double entropy = analyze_entropy(current_data, current_size);
    printf("    Entropy: %.2f bits/byte\n", entropy);
  }

  // STAGE 1: PRE-PROCESSING (BWT + MTF + RLE)
  result->preprocess = preprocess_encode(current_data, current_size);
  if (result->preprocess) {
    current_data = result->preprocess->data;
    current_size = result->preprocess->size;

    if (g_verbose) {
      printf("    After preprocessing: %u bytes (%.1f%%)\n", current_size,
             (double)current_size / chunk->original_size * 100);
    }
  }

  // STAGE 2: PREDICTION (Context + Delta)
  result->prediction = prediction_encode(current_data, current_size);
  if (result->prediction) {
    current_data = result->prediction->data;
    current_size = result->prediction->size;

    if (g_verbose) {
      printf("    After prediction: %u bytes (%.1f%%)\n", current_size,
             (double)current_size / chunk->original_size * 100);
    }
  }

  // STAGE 3: COMPRESSION (TODO: LZ4 + Huffman + ANS)
  // Per ora skippiamo, ma i dati sono già compressi da preprocessing+prediction

  // STAGE 4: OBFUSCATION
  result->obfuscation =
      obfuscate_data(current_data, current_size, &ctx->obfuscation);
  if (result->obfuscation) {
    current_data = result->obfuscation->data;
    current_size = result->obfuscation->size;

    if (g_verbose) {
      printf("    After obfuscation: %u bytes (%.1f%%)\n", current_size,
             (double)current_size / chunk->original_size * 100);
    }
  }

  // Aggiorna chunk con dati processati
  if (chunk->data) {
    secure_zero(chunk->data, chunk->encrypted_size);
    free(chunk->data);
  }

  chunk->data = malloc(current_size);
  if (chunk->data) {
    memcpy(chunk->data, current_data, current_size);
    chunk->compressed_size = current_size;
    chunk->encrypted_size = current_size; // Prima di encryption
  }

  // STAGE 5: ENCRYPTION (TODO: AES-256-GCM con Argon2)
  // Verrà fatto dopo, chunk per chunk

  return result;
}

// Deprocessa chunk (ordine inverso)
bool process_chunk_decompress(Chunk *chunk, ChunkPipelineResult *pipeline) {
  if (!chunk || !pipeline)
    return false;

  uint8_t *temp1 = malloc(chunk->encrypted_size * 2);
  uint8_t *temp2 = malloc(chunk->encrypted_size * 2);
  uint8_t *temp3 = malloc(chunk->encrypted_size * 2);

  if (!temp1 || !temp2 || !temp3) {
    free(temp1);
    free(temp2);
    free(temp3);
    return false;
  }

  const uint8_t *current_data = chunk->data;
  uint32_t current_size = chunk->encrypted_size;

  // STAGE 1: DEOBFUSCATION
  if (pipeline->obfuscation) {
    if (!deobfuscate_data(current_data, current_size, pipeline->obfuscation,
                          temp1)) {
      free(temp1);
      free(temp2);
      free(temp3);
      return false;
    }
    current_data = temp1;
    current_size = pipeline->obfuscation->original_size;
  }

  // STAGE 2: DECOMPRESS (TODO)

  // STAGE 3: PREDICTION DECODE
  if (pipeline->prediction) {
    if (!prediction_decode(current_data, current_size, pipeline->prediction,
                           temp2, current_size)) {
      free(temp1);
      free(temp2);
      free(temp3);
      return false;
    }
    current_data = temp2;
  }

  // STAGE 4: PREPROCESS DECODE
  if (pipeline->preprocess) {
    uint32_t decoded_size;
    if (!preprocess_decode(current_data, current_size, pipeline->preprocess,
                           temp3, &decoded_size)) {
      free(temp1);
      free(temp2);
      free(temp3);
      return false;
    }
    current_data = temp3;
    current_size = decoded_size;
  }

  // Copia risultato finale
  if (chunk->data)
    free(chunk->data);
  chunk->data = malloc(current_size);
  if (!chunk->data) {
    free(temp1);
    free(temp2);
    free(temp3);
    return false;
  }

  memcpy(chunk->data, current_data, current_size);
  chunk->original_size = current_size;

  free(temp1);
  free(temp2);
  free(temp3);

  return true;
}

void pipeline_result_free(ChunkPipelineResult *result) {
  if (!result)
    return;

  if (result->preprocess)
    preprocess_result_free(result->preprocess);
  if (result->prediction)
    prediction_result_free(result->prediction);
  if (result->obfuscation)
    obfuscation_result_free(result->obfuscation);

  free(result);
}

// ============================================================================
// FILE COMPRESSION
// ============================================================================

StatusCode compress_file(const char *input_path, const char *output_path,
                         ProcessContext *ctx) {
  if (!input_path || !output_path || !ctx) {
    return STATUS_ERROR_IO;
  }

  double start_time = get_time();

  printf("Compressing: %s -> %s\n", input_path, output_path);

  // Open input
  ChunkReader *reader = chunker_open_read(input_path);
  if (!reader) {
    print_error(STATUS_ERROR_IO, "Cannot open input file");
    return STATUS_ERROR_IO;
  }

  chunker_print_info(reader);

  // Open output
  ChunkWriter *writer = chunker_open_write(output_path);
  if (!writer) {
    chunker_close_read(reader);
    print_error(STATUS_ERROR_IO, "Cannot create output file");
    return STATUS_ERROR_IO;
  }

  // Aggiorna header
  ctx->header.chunk_count = reader->total_chunks;
  ctx->header.total_size = reader->file_size;

  // TODO: Scrivi header nel file

  // Processa chunks
  uint32_t chunks_processed = 0;
  ChunkPipelineResult **pipelines =
      calloc(reader->total_chunks, sizeof(ChunkPipelineResult *));

  while (chunks_processed < reader->total_chunks) {
    progress_callback((float)chunks_processed / reader->total_chunks * 100.0f,
                      "Processing chunks");

    Chunk *chunk = chunker_read_next(reader);
    if (!chunk) {
      print_error(STATUS_ERROR_IO, "Failed to read chunk");
      break;
    }

    // Process chunk attraverso pipeline
    pipelines[chunks_processed] = process_chunk_compress(chunk, ctx);

    // Write processed chunk
    if (!chunker_write_chunk(writer, chunk)) {
      chunk_free(chunk);
      print_error(STATUS_ERROR_IO, "Failed to write chunk");
      break;
    }

    ctx->bytes_processed += chunk->original_size;
    ctx->bytes_written += chunk->encrypted_size;

    chunk_free(chunk);
    chunks_processed++;
  }

  progress_callback(100.0f, "Complete");

  // Cleanup
  chunker_close_read(reader);
  chunker_close_write(writer);

  for (uint32_t i = 0; i < chunks_processed; i++) {
    pipeline_result_free(pipelines[i]);
  }
  free(pipelines);

  // Stats finali
  double elapsed = get_time() - start_time;
  ctx->time_elapsed = elapsed;
  ctx->compression_ratio = (double)ctx->bytes_written / ctx->bytes_processed;

  printf("\n=== COMPRESSION STATS ===\n");
  printf("Original size: %llu bytes (%.2f MB)\n",
         (unsigned long long)ctx->bytes_processed,
         ctx->bytes_processed / (1024.0 * 1024.0));
  printf("Compressed size: %llu bytes (%.2f MB)\n",
         (unsigned long long)ctx->bytes_written,
         ctx->bytes_written / (1024.0 * 1024.0));
  printf("Ratio: %.2f%%\n", ctx->compression_ratio * 100);
  printf("Time: %.2f seconds (%.2f MB/s)\n", elapsed,
         (ctx->bytes_processed / (1024.0 * 1024.0)) / elapsed);

  return STATUS_OK;
}

// ============================================================================
// FILE DECOMPRESSION
// ============================================================================

StatusCode decompress_file(const char *input_path, const char *output_path,
                           ProcessContext *ctx) {
  printf("Decompressing: %s -> %s\n", input_path, output_path);

  // TODO: Implementa decompressione completa
  // 1. Leggi header
  // 2. Leggi chunks
  // 3. Decrypt + deobfuscate + decompress ogni chunk
  // 4. Ricostruisci file originale

  printf("Decompression not yet fully implemented\n");
  return STATUS_ERROR_FORMAT;
}

// ============================================================================
// MAIN
// ============================================================================

void print_usage(const char *prog) {
  printf("Usage:\n");
  printf("  %s compress <input> <output> [options]\n", prog);
  printf("  %s decompress <input> <output> [options]\n", prog);
  printf("\nOptions:\n");
  printf("  -p <password>    Use password for encryption\n");
  printf("  -v               Verbose output\n");
  printf("  -q               Quiet (no progress)\n");
  printf("  --no-obfuscate   Disable obfuscation\n");
  printf("  --fast           Fast mode (less compression)\n");
  printf("  --paranoid       Maximum security\n");
}

int main(int argc, char **argv) {
  if (argc < 4) {
    print_usage(argv[0]);
    return 1;
  }

  const char *command = argv[1];
  const char *input = argv[2];
  const char *output = argv[3];

  // Parse options
  const char *password = NULL;
  bool obfuscate = true;

  for (int i = 4; i < argc; i++) {
    if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
      password = argv[++i];
    } else if (strcmp(argv[i], "-v") == 0) {
      g_verbose = true;
    } else if (strcmp(argv[i], "-q") == 0) {
      g_show_progress = false;
      g_verbose = false;
    } else if (strcmp(argv[i], "--no-obfuscate") == 0) {
      obfuscate = false;
    }
  }

  // Crea context
  ProcessContext *ctx = context_create();
  if (!ctx) {
    fprintf(stderr, "Failed to create context\n");
    return 1;
  }

  // Configura obfuscation
  if (!obfuscate) {
    ctx->obfuscation.type = OBFUSCATE_NONE;
  }

  // Configura password
  if (password) {
    strncpy(ctx->password, password, sizeof(ctx->password) - 1);
    ctx->use_password = true;
  }

  StatusCode status;

  if (strcmp(command, "compress") == 0) {
    status = compress_file(input, output, ctx);
  } else if (strcmp(command, "decompress") == 0) {
    status = decompress_file(input, output, ctx);
  } else {
    fprintf(stderr, "Unknown command: %s\n", command);
    context_free(ctx);
    return 1;
  }

  context_free(ctx);

  if (status != STATUS_OK) {
    fprintf(stderr, "Operation failed: %s\n", status_to_string(status));
    return 1;
  }

  return 0;
}
