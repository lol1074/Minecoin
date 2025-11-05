#include "type.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct  
{
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


ChunkReader* chunker_open(const char* filename) {
    if (!filename) return;

    ChunkReader *reader = calloc(1, sizeof(ChunkReader));
    if (!reader) return;

    reader->input_file = fopen(filename, "rb");
    if (!reader->input_file) {
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


void chunker_close(ChunkReader *reader) {
    if (!reader) return;

    if (reader->input_file) {
        fclose(reader->input_file);
    }

    free(reader);
}

Chunk *chunk_read_prs(ChunkReader *reader) {
    if (!reader || reader->eof_reached) return;

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

    out = count;
    return chunks;
}

