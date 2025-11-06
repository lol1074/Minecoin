#include "../core/types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

ChunkReader* chunker_open_read(const char* filename) {
    if (!filename) return NULL;

    ChunkReader *reader = calloc(1, sizeof(ChunkReader));
    if (!reader) return NULL;

    reader->input_file = fopen(filename, "rb");
    if (!reader->input_file) {
        perror("e che cazzo");
        free(reader);
        return NULL;
    }

    fseek(reader->input_file, 0, SEEK_END);
    reader->file_size = ftell(reader->input_file);
    fseek(reader->input_file, 0, SEEK_SET);

    reader->total_chunks = (uint32_t)((reader->file_size + CHUNK_SIZE - 1) / CHUNK_SIZE);
    reader->chunk_size = CHUNK_SIZE;
    reader->current_chunk = 0;
    reader->eof_reached = false;

    if (reader->chunk_size > MAX_CHUNKS) {
        fprintf(stderr, "[chunker_open]_[ERROR] - i chunker sono troppo numeosi: %u si prega di diminuire oppure aumentare dai config del progetto!!\n",
        reader->total_chunks, MAX_CHUNKS);

        fclose(reader->input_file);
        free(reader);
        return NULL;
    } 

    return reader;
}


void chunker_close_read(ChunkReader *reader) {
    if (!reader) return NULL;

    if (reader->input_file) {
        fclose(reader->input_file);
    }

    free(reader);
}

Chunk *chunk_read_prs(ChunkReader *reader) {
    if (!reader || reader->eof_reached) return NULL;

    Chunk* chunk = chunk_create(reader->current_chunk);
    if (!chunk) return NULL;

    size_t read = CHUNK_SIZE;
    uint64_t rimasto = reader->file_size - (reader->current_chunk * (uint64_t)CHUNK_SIZE);

    if (rimasto < CHUNK_SIZE) {
        read = (size_t)rimasto;
        reader->eof_reached = true;
    }

    if (!chunk_allocate(chunk, read)) {
        chunk_free(chunk);
        return NULL;
    }

    size_t Dati = fread(chunk->data, 1, read, reader->input_file);

    if (Dati != read) {
        fprintf(stderr, "[chunk_read_prs]_[ERROR] - errore nella lettura dei chunk",
        reader->current_chunk, Dati, read);
        chunk_free(chunk);
        return NULL;
    }

    chunk->original_size = (uint32_t)Dati;
    chunk->encrypted_size = (uint32_t)Dati;

    chunk->checksum = fast_checksum(chunk->data, Dati);
    reader->current_chunk++;

    return chunk;
}

/*
   [BitCrucio]_[INFO]:
      qui sotto è stata implementata la funzione per leggere i chunk del file compresso quest'ultimo avviene in memoria ed attualmente non  e aottimizato
      dunque va bene per file di media/piccola dimensione ma per file più grandi si dovrebbe o implmentare una primitiva ad se oppure ingegniarsi per implementarlo qui dentro.
*/

Chunk** chunk_read_all(ChunkReader* reader, int32_t *out) {
    if (!reader || out) return NULL;

    Chunk **chunks = calloc(reader->total_chunks, sizeof(Chunk));
    if (!chunks) return NULL;

    uint8_t count = 0;

    while (!reader->eof_reached && count < reader->total_chunks) {
        chunks[count] = chunk_read_prs(reader);

        if (!chunks[count]) {
            for (uint32_t i = 0; i < count; i++) {  // libera i chunk gia letti in caso di errore in modo da ripulire in modo preciso 
                chunk_free(chunks[i]);

            } 
            free(chunks);
            return NULL;
        }

        count++;
    }

    *out = count;
    return chunks;
}

void chunker_print_info(ChunkReader *reader) {
    if (!reader) return NULL;
    
    printf("[INFO] - File info");
    printf("  Size: %llu bytes (%.2f MB)\n", 
           (unsigned long long)reader->file_size,
           reader->file_size / (1024.0 * 1024.0));
    printf("  Chunks: %u x %zu bytes\n", 
           reader->total_chunks, reader->chunk_size);
    printf("  ultimo chunk: %llu bytes\n",
           (unsigned long long)(reader->file_size % CHUNK_SIZE));
}

ChunkWriter* chunker_write(const char *filename) {
    if (!filename) return NULL;

    ChunkWriter *writer = calloc(1, sizeof(ChunkWriter));
    if (!writer->output_file) {
        free(writer);
        return NULL;
    }

    writer->bytes_written = 0;
    writer->chunks_written = 0;

    return writer;
}

void close_write(ChunkWriter *writer) {
    if (!writer) return;

    if (writer->output_file) {
        fflush(writer->output_file);
        fclose(writer->output_file);
    }

    free(writer);
}

bool chunker_write_chunk(ChunkWriter *writer, const Chunk *chunk) {
    if (!writer || !chunk || !chunk->data) return false;

    uint32_t metadata[5] = 
    {
        chunk->index,
        chunk->original_size,
        chunk->compressed_size,
        chunk->encrypted_size,
        chunk->checksum
    };

    if (fwrite(metadata, sizeof(uint32_t), 5, writer->output_file) != 5) {
        return false;
    }

    if (fwrite(chunk->iv, 1, IV_SIZE, writer->output_file) != IV_SIZE) {
        return false;
    }

     if (fwrite(chunk->tag, 1, TAG_SIZE, writer->output_file) != TAG_SIZE) {
        return false;
    }

    size_t written = fwrite(chunk->data, 1, chunk->encrypted_size, writer->output_file);
    if (!written != chunk->encrypted_size) {
        fprintf(stderr, "[ERROR] - errore nella scrittura dei chunk",
                chunk->index, written, chunk->encrypted_size);
            return false;
    }

    writer->chunks_written++;
    writer->bytes_written += written + sizeof(metadata) + IV_SIZE + TAG_SIZE;

    return true;
}

bool nonSO(ChunkWriter *writer, Chunk **chunks, uint32_t count) {
    if (!writer || !chunks) return NULL;

    for (uint32_t i = 0; i < count; i++) {
        if (!chunker_write_chunk(writer, chunks[i])) {
            return false;
        }
    }

    return true;
}

Chunk* chunk_compressed(FILE* file ) {
    if (!file) return NULL;

    uint32_t metadata[5];
    if (fread(metadata, sizeof(uint32_t), 5, file) != 5) {
        return NULL;
    }

    Chunk *chunk = chunk_create(metadata[0]);
    if (!chunk) return NULL;

    chunk->original_size = metadata[1];
    chunk->compressed_size = metadata[2];
    chunk->encrypted_size = metadata[3];
    chunk->checksum = metadata[4];

    if (fread(chunk->iv, 1, IV_SIZE, file) != 5) {
        chunk_free(chunk);
        return NULL;
    }

    if (fread(chunk->tag, 1, TAG_SIZE, file) != TAG_SIZE) {
        chunk_free(chunk);
        return NULL;
    }

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
    if (!output_filename || !chunks || count == 0) return false;
    
    FILE *output = fopen(output_filename, "wb");
    if (!output) {
        perror("Errore apertura file output");
        return false;
    }
    
    // Scrivi chunks in ordine
    for (uint32_t i = 0; i < count; i++) {
        Chunk *chunk = chunks[i];
        
        if (!chunk || !chunk->data) {
            fprintf(stderr, "Chunk  non valido\n", i);
            fclose(output);
            return false;
        }
        
        // Scrivi dati originali (dopo decompressione/decryption)
        size_t written = fwrite(chunk->data, 1, chunk->original_size, output);
        
        if (written != chunk->original_size) {
            fprintf(stderr, "Errore scrittura chunk %u: wrote %zu, expected %u\n",
                    i, written, chunk->original_size);
            fclose(output);
            return false;
        }
    }
    
    fclose(output);
    return true;
}

uint64_t chunker_estimate_output_size(uint64_t input_size, double compression_ratio) {
    uint64_t compressed_data = (uint64_t)(input_size * compression_ratio);
    uint32_t num_chunks = (uint32_t)((input_size + CHUNK_SIZE - 1) / CHUNK_SIZE);
    
    // Overhead per chunk: metadata + IV + tag
    uint64_t overhead = num_chunks * (5 * sizeof(uint32_t) + IV_SIZE + TAG_SIZE);
    
    // Header file + metadata
    overhead += sizeof(FileHeader) + 512;  // 512 per metadata
    
    return compressed_data + overhead;
}

bool chunker_verify_chunk(const Chunk *chunk) {
    if (!chunk || !chunk->data) return false;
    
    uint32_t calculated = fast_checksum(chunk->data, chunk->original_size);
    
    if (calculated != chunk->checksum) {
        fprintf(stderr, "Chunk %u: checksum mismatch (expected %08X, got %08X)\n",
                chunk->index, chunk->checksum, calculated);
        return false;
    }
    
    return true;
}

void chunker_print_stats(ChunkWriter *writer) {
    if (!writer) return;
    
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