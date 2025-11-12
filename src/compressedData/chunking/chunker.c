#include "../core/types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================================
// CHUNK READER - LETTURA FILE
// Note: ChunkReader e ChunkWriter sono definiti in core/types.h
// ============================================================================

ChunkReader* chunker_open_read(const char *filename) {
    if (!filename)
        return NULL;

    ChunkReader *reader = calloc(1, sizeof(ChunkReader));
    if (!reader)
        return NULL;

    reader->input_file = fopen(filename, "rb");
    if (!reader->input_file) {
        perror("[chunker_open_read] ERROR opening file");
        free(reader);
        return NULL;
    }

    // Determina dimensione file
    fseek(reader->input_file, 0, SEEK_END);
    reader->file_size = ftell(reader->input_file);
    fseek(reader->input_file, 0, SEEK_SET);

    // Calcola numero chunks necessari
    reader->total_chunks = (uint32_t)((reader->file_size + CHUNK_SIZE - 1) / CHUNK_SIZE);
    reader->chunk_size = CHUNK_SIZE;
    reader->current_chunk = 0;
    reader->eof_reached = false;

    // Controllo dimensione massima
    if (reader->total_chunks > MAX_CHUNKS) {
        fprintf(stderr, "[chunker_open_read] ERROR: File troppo grande: %u chunks (max %u)\n",
                reader->total_chunks, MAX_CHUNKS);
        fclose(reader->input_file);
        free(reader);
        return NULL;
    }

    // Permetti anche file molto piccoli (0 chunks -> 1 chunk)
    if (reader->total_chunks == 0) {
        reader->total_chunks = 1;
    }

    return reader;
}

void chunker_close_read(ChunkReader *reader) {
    if (!reader)
        return;

    if (reader->input_file) {
        fclose(reader->input_file);
    }

    free(reader);
}

// Leggi prossimo chunk
Chunk* chunker_read_next(ChunkReader *reader) {
    if (!reader || reader->eof_reached)
        return NULL;

    Chunk *chunk = chunk_create(reader->current_chunk);
    if (!chunk)
        return NULL;

    // Alloca buffer per chunk
    size_t to_read = CHUNK_SIZE;
    uint64_t remaining = reader->file_size - (reader->current_chunk * (uint64_t)CHUNK_SIZE);

    if (remaining < CHUNK_SIZE) {
        to_read = (size_t)remaining;
        reader->eof_reached = true;
    }

    if (!chunk_allocate(chunk, to_read)) {
        chunk_free(chunk);
        return NULL;
    }

    // Leggi dati
    size_t read_bytes = fread(chunk->data, 1, to_read, reader->input_file);

    if (read_bytes != to_read) {
        fprintf(stderr, "[chunker_read_next] ERROR: Chunk %u read %zu, expected %zu\n",
                reader->current_chunk, read_bytes, to_read);
        chunk_free(chunk);
        return NULL;
    }

    chunk->original_size = (uint32_t)read_bytes;
    chunk->encrypted_size = (uint32_t)read_bytes;

    // Calcola checksum del chunk originale
    chunk->checksum = fast_checksum(chunk->data, read_bytes);

    reader->current_chunk++;

    return chunk;
}

// Leggi tutti chunks in memoria (per file piccoli)
Chunk** chunker_read_all(ChunkReader *reader, uint32_t *out_count) {
    if (!reader || !out_count)
        return NULL;

    Chunk **chunks = calloc(reader->total_chunks, sizeof(Chunk*));
    if (!chunks)
        return NULL;

    uint32_t count = 0;

    while (!reader->eof_reached && count < reader->total_chunks) {
        chunks[count] = chunker_read_next(reader);

        if (!chunks[count]) {
            // Errore: libera chunks già letti
            for (uint32_t i = 0; i < count; i++) {
                chunk_free(chunks[i]);
            }
            free(chunks);
            return NULL;
        }

        count++;
    }

    *out_count = count;
    return chunks;
}

// Info su chunk reader
void chunker_print_info(ChunkReader *reader) {
    if (!reader)
        return;

    printf("File info:\n");
    printf("  Size: %llu bytes (%.2f MB)\n",
           (unsigned long long)reader->file_size,
           reader->file_size / (1024.0 * 1024.0));
    printf("  Chunks: %u x %zu bytes\n",
           reader->total_chunks, reader->chunk_size);
    printf("  Last chunk: %llu bytes\n",
           (unsigned long long)(reader->file_size % CHUNK_SIZE));
}

// ============================================================================
// CHUNK WRITER - SCRITTURA FILE
// ============================================================================

ChunkWriter* chunker_open_write(const char *filename) {
    if (!filename)
        return NULL;

    ChunkWriter *writer = calloc(1, sizeof(ChunkWriter));
    if (!writer)
        return NULL;

    writer->output_file = fopen(filename, "wb");
    if (!writer->output_file) {
        perror("[chunker_open_write] ERROR creating file");
        free(writer);
        return NULL;
    }

    writer->chunks_written = 0;
    writer->bytes_written = 0;

    return writer;
}

void chunker_close_write(ChunkWriter *writer) {
    if (!writer)
        return;

    if (writer->output_file) {
        fflush(writer->output_file);
        fclose(writer->output_file);
    }

    free(writer);
}

// Scrivi singolo chunk
bool chunker_write_chunk(ChunkWriter *writer, const Chunk *chunk) {
    if (!writer || !chunk || !chunk->data)
        return false;

    // Scrivi metadata chunk (per ricostruzione)
    uint32_t metadata[5] = {
        chunk->index,
        chunk->original_size,
        chunk->compressed_size,
        chunk->encrypted_size,
        chunk->checksum
    };

    if (fwrite(metadata, sizeof(uint32_t), 5, writer->output_file) != 5) {
        return false;
    }

    // Scrivi IV
    if (fwrite(chunk->iv, 1, IV_SIZE, writer->output_file) != IV_SIZE) {
        return false;
    }

    // Scrivi auth tag
    if (fwrite(chunk->tag, 1, TAG_SIZE, writer->output_file) != TAG_SIZE) {
        return false;
    }

    // Scrivi dati chunk
    size_t written = fwrite(chunk->data, 1, chunk->encrypted_size, writer->output_file);

    if (written != chunk->encrypted_size) {
        fprintf(stderr, "[chunker_write_chunk] ERROR: Chunk %u wrote %zu, expected %u\n",
                chunk->index, written, chunk->encrypted_size);
        return false;
    }

    writer->chunks_written++;
    writer->bytes_written += written + sizeof(metadata) + IV_SIZE + TAG_SIZE;

    return true;
}

// Scrivi array di chunks
bool chunker_write_all(ChunkWriter *writer, Chunk **chunks, uint32_t count) {
    if (!writer || !chunks)
        return false;

    for (uint32_t i = 0; i < count; i++) {
        if (!chunker_write_chunk(writer, chunks[i])) {
            return false;
        }
    }

    return true;
}

// ============================================================================
// CHUNK RECONSTRUCTION (DECOMPRESSIONE)
// ============================================================================

// Leggi singolo chunk da file compresso
Chunk* chunker_read_compressed_chunk(FILE *file) {
    if (!file)
        return NULL;

    // Leggi metadata
    uint32_t metadata[5];
    if (fread(metadata, sizeof(uint32_t), 5, file) != 5) {
        return NULL;
    }

    Chunk *chunk = chunk_create(metadata[0]);
    if (!chunk)
        return NULL;

    chunk->original_size = metadata[1];
    chunk->compressed_size = metadata[2];
    chunk->encrypted_size = metadata[3];
    chunk->checksum = metadata[4];

    // Leggi IV
    if (fread(chunk->iv, 1, IV_SIZE, file) != IV_SIZE) {
        chunk_free(chunk);
        return NULL;
    }

    // Leggi auth tag
    if (fread(chunk->tag, 1, TAG_SIZE, file) != TAG_SIZE) {
        chunk_free(chunk);
        return NULL;
    }

    // Alloca e leggi dati
    if (!chunk_allocate(chunk, chunk->encrypted_size)) {
        chunk_free(chunk);
        return NULL;
    }

    if (fread(chunk->data, 1, chunk->encrypted_size, file) != chunk->encrypted_size) {
        chunk_free(chunk);
        return NULL;
    }

    return chunk;
}

// Ricostruisci file da chunks
bool chunker_reconstruct_file(const char *output_filename, Chunk **chunks, uint32_t count) {
    if (!output_filename || !chunks || count == 0)
        return false;

    FILE *output = fopen(output_filename, "wb");
    if (!output) {
        perror("[chunker_reconstruct_file] ERROR opening output");
        return false;
    }

    // Scrivi chunks in ordine
    for (uint32_t i = 0; i < count; i++) {
        Chunk *chunk = chunks[i];

        if (!chunk || !chunk->data) {
            fprintf(stderr, "[chunker_reconstruct_file] ERROR: Chunk %u invalid\n", i);
            fclose(output);
            return false;
        }

        // Scrivi dati originali (dopo decompressione/decryption)
        size_t written = fwrite(chunk->data, 1, chunk->original_size, output);

        if (written != chunk->original_size) {
            fprintf(stderr, "[chunker_reconstruct_file] ERROR: Chunk %u wrote %zu, expected %u\n",
                    i, written, chunk->original_size);
            fclose(output);
            return false;
        }
    }

    fclose(output);
    return true;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

// Calcola dimensione totale file compresso (stima)
uint64_t chunker_estimate_output_size(uint64_t input_size, double compression_ratio) {
    // Stima conservativa
    uint64_t compressed_data = (uint64_t)(input_size * compression_ratio);
    uint32_t num_chunks = (uint32_t)((input_size + CHUNK_SIZE - 1) / CHUNK_SIZE);

    // Overhead per chunk: metadata + IV + tag
    uint64_t overhead = num_chunks * (5 * sizeof(uint32_t) + IV_SIZE + TAG_SIZE);

    // Header file + metadata
    overhead += 1024;  // 1KB per header e metadata

    return compressed_data + overhead;
}

// Verifica integrità chunk
bool chunker_verify_chunk(const Chunk *chunk) {
    if (!chunk || !chunk->data)
        return false;

    // Ricalcola checksum e confronta
    uint32_t calculated = fast_checksum(chunk->data, chunk->original_size);

    if (calculated != chunk->checksum) {
        fprintf(stderr, "[chunker_verify_chunk] ERROR: Chunk %u checksum mismatch (expected %08X, got %08X)\n",
                chunk->index, chunk->checksum, calculated);
        return false;
    }

    return true;
}

// Statistiche chunking
void chunker_print_stats(ChunkWriter *writer) {
    if (!writer)
        return;

    printf("Chunking stats:\n");
    printf("  Chunks written: %u\n", writer->chunks_written);
    printf("  Bytes written: %llu (%.2f MB)\n",
           (unsigned long long)writer->bytes_written,
           writer->bytes_written / (1024.0 * 1024.0));

    if (writer->chunks_written > 0) {
        printf("  Avg chunk size: %llu bytes\n",
               (unsigned long long)(writer->bytes_written / writer->chunks_written));
    }
}