#include "../core/types.h"

extern ChunkReader* chunker_open_read(const char *filename);
extern void chunker_close_read(ChunkReader *reader);
extern Chunk* chunker_read_next(ChunkReader *reader);
extern void chunker_print_info(ChunkReader *reader);
extern ChunkWriter* chunker_open_write(const char *filename);
extern void chunker_close_write(ChunkWriter *writer);
extern bool chunker_write_chunk(ChunkWriter *writer, const Chunk *chunk);
extern bool chunker_reconstruct_file(const char *output, Chunk **chunks, uint32_t count);