#include "../core/types.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

// ============================================================================
// POLYMORPHIC ENCODING
// ============================================================================

typedef struct {
    uint32_t seed;
    uint8_t key_stream[256];
    uint32_t key_pos;
} PolymorphicState;

// Genera key stream pseudo-random (basato su seed)
static void generate_key_stream(PolymorphicState *state) {
    uint32_t s = state->seed;
    
    for (int i = 0; i < 256; i++) {
        // Linear congruential generator
        s = (s * 1103515245 + 12345) & 0x7FFFFFFF;
        state->key_stream[i] = (uint8_t)(s >> 16);
    }
    
    state->key_pos = 0;
}

// Crea stato polymorphic
PolymorphicState* polymorphic_create(uint32_t seed) {
    PolymorphicState *state = calloc(1, sizeof(PolymorphicState));
    if (!state) return NULL;
    
    state->seed = seed;
    generate_key_stream(state);
    
    return state;
}

void polymorphic_free(PolymorphicState *state) {
    if (!state) return;
    secure_zero(state, sizeof(PolymorphicState));
    free(state);
}

// Encoding polymorphic (ogni byte trasformato diversamente)
Buffer* polymorphic_encode(const uint8_t *input, uint32_t size, uint32_t seed) {
    if (!input || size == 0) return NULL;
    
    PolymorphicState *state = polymorphic_create(seed);
    if (!state) return NULL;
    
    Buffer *output = buffer_create(size + 4);  // +4 per seed
    if (!output) {
        polymorphic_free(state);
        return NULL;
    }
    
    // Scrivi seed all'inizio
    buffer_append(output, &seed, sizeof(seed));
    
    for (uint32_t i = 0; i < size; i++) {
        // Rigenera key stream ogni 256 byte
        if (state->key_pos >= 256) {
            state->seed = state->seed * 69069 + 1;
            generate_key_stream(state);
        }
        
        uint8_t key = state->key_stream[state->key_pos++];
        
        // Trasformazione polimorfica: XOR + rotazione + sostituzione
        uint8_t byte = input[i];
        byte ^= key;
        byte = (byte << 3) | (byte >> 5);  // Rotazione
        byte ^= (uint8_t)(i & 0xFF);        // XOR con posizione
        
        buffer_append(output, &byte, 1);
    }
    
    polymorphic_free(state);
    return output;
}

// Decoding polymorphic
bool polymorphic_decode(const uint8_t *input, uint32_t size, uint8_t *output) {
    if (!input || !output || size < 4) return false;
    
    // Leggi seed
    uint32_t seed;
    memcpy(&seed, input, sizeof(seed));
    input += sizeof(seed);
    size -= sizeof(seed);
    
    PolymorphicState *state = polymorphic_create(seed);
    if (!state) return false;
    
    for (uint32_t i = 0; i < size; i++) {
        if (state->key_pos >= 256) {
            state->seed = state->seed * 69069 + 1;
            generate_key_stream(state);
        }
        
        uint8_t key = state->key_stream[state->key_pos++];
        uint8_t byte = input[i];
        
        // Operazioni inverse
        byte ^= (uint8_t)(i & 0xFF);
        byte = (byte >> 3) | (byte << 5);  // Rotazione inversa
        byte ^= key;
        
        output[i] = byte;
    }
    
    polymorphic_free(state);
    return true;
}

// ============================================================================
// FAKE DATA INJECTION
// ============================================================================

// Genera posizioni casuali per fake data
static uint32_t* generate_fake_positions(uint32_t data_size, uint32_t fake_count, uint32_t seed) {
    if (fake_count == 0) return NULL;
    
    uint32_t *positions = malloc(fake_count * sizeof(uint32_t));
    if (!positions) return NULL;
    
    // RNG per posizioni
    uint32_t rng = seed;
    
    for (uint32_t i = 0; i < fake_count; i++) {
        rng = rng * 1103515245 + 12345;
        positions[i] = rng % (data_size + fake_count);
    }
    
    // Ordina posizioni
    for (uint32_t i = 0; i < fake_count - 1; i++) {
        for (uint32_t j = i + 1; j < fake_count; j++) {
            if (positions[i] > positions[j]) {
                uint32_t temp = positions[i];
                positions[i] = positions[j];
                positions[j] = temp;
            }
        }
    }
    
    return positions;
}

// Inietta fake data
Buffer* fake_data_inject(const uint8_t *input, uint32_t size, 
                         uint32_t fake_percent, uint32_t seed,
                         FakeDataMap **out_map) {
    if (!input || size == 0 || fake_percent == 0 || fake_percent > 50) {
        return NULL;
    }
    
    // Calcola quanti fake bytes iniettare
    uint32_t fake_count = (size * fake_percent) / 100;
    if (fake_count == 0) fake_count = 1;
    
    FakeDataMap *map = calloc(1, sizeof(FakeDataMap));
    if (!map) return NULL;
    
    map->fake_positions = generate_fake_positions(size, fake_count, seed);
    if (!map->fake_positions) {
        free(map);
        return NULL;
    }
    
    map->fake_count = fake_count;
    map->real_size = size;
    
    Buffer *output = buffer_create(size + fake_count);
    if (!output) {
        free(map->fake_positions);
        free(map);
        return NULL;
    }
    
    // RNG per generare fake bytes
    uint32_t rng = seed ^ 0xDEADBEEF;
    
    uint32_t real_pos = 0;
    uint32_t fake_idx = 0;
    
    for (uint32_t out_pos = 0; out_pos < size + fake_count; out_pos++) {
        // Controlla se questa posizione è fake
        bool is_fake = false;
        
        if (fake_idx < fake_count && out_pos == map->fake_positions[fake_idx]) {
            is_fake = true;
            fake_idx++;
        }
        
        if (is_fake) {
            // Genera fake byte (sembra credibile)
            rng = rng * 1103515245 + 12345;
            uint8_t fake_byte = (uint8_t)(rng >> 16);
            buffer_append(output, &fake_byte, 1);
        } else {
            // Byte reale
            buffer_append(output, &input[real_pos++], 1);
        }
    }
    
    if (out_map) *out_map = map;
    
    return output;
}

// Rimuovi fake data
bool fake_data_remove(const uint8_t *input, uint32_t size,
                     const FakeDataMap *map, uint8_t *output) {
    if (!input || !output || !map) return false;
    
    uint32_t out_pos = 0;
    uint32_t fake_idx = 0;
    
    for (uint32_t in_pos = 0; in_pos < size; in_pos++) {
        // Controlla se questa posizione è fake
        bool is_fake = false;
        
        if (fake_idx < map->fake_count && in_pos == map->fake_positions[fake_idx]) {
            is_fake = true;
            fake_idx++;
        }
        
        if (!is_fake) {
            output[out_pos++] = input[in_pos];
        }
    }
    
    return (out_pos == map->real_size);
}

void fake_data_map_free(FakeDataMap *map) {
    if (!map) return;
    
    if (map->fake_positions) {
        free(map->fake_positions);
    }
    
    free(map);
}

// ============================================================================
// STRUCTURE RANDOMIZATION
// ============================================================================

// Genera permutazione casuale (Fisher-Yates)
static uint32_t* generate_permutation(uint32_t count, uint32_t seed) {
    if (count == 0) return NULL;
    
    uint32_t *perm = malloc(count * sizeof(uint32_t));
    if (!perm) return NULL;
    
    // Inizializza identità
    for (uint32_t i = 0; i < count; i++) {
        perm[i] = i;
    }
    
    // Fisher-Yates shuffle
    uint32_t rng = seed;
    
    for (uint32_t i = count - 1; i > 0; i--) {
        rng = rng * 1103515245 + 12345;
        uint32_t j = rng % (i + 1);
        
        uint32_t temp = perm[i];
        perm[i] = perm[j];
        perm[j] = temp;
    }
    
    return perm;
}

// Shuffle blocchi di dati
Buffer* structure_shuffle(const uint8_t *input, uint32_t size,
                         uint32_t seed, ShuffleMap **out_map) {
    if (!input || size == 0) return NULL;
    
    // Dividi in blocchi da 1KB
    uint32_t block_size = 1024;
    uint32_t block_count = (size + block_size - 1) / block_size;
    
    if (block_count <= 1) {
        // Troppo piccolo per shuffle
        return NULL;
    }
    
    ShuffleMap *map = calloc(1, sizeof(ShuffleMap));
    if (!map) return NULL;
    
    map->permutation = generate_permutation(block_count, seed);
    if (!map->permutation) {
        free(map);
        return NULL;
    }
    
    map->block_count = block_count;
    map->block_size = block_size;
    
    Buffer *output = buffer_create(size);
    if (!output) {
        free(map->permutation);
        free(map);
        return NULL;
    }
    
    // Scrivi blocchi in ordine shuffled
    for (uint32_t i = 0; i < block_count; i++) {
        uint32_t src_block = map->permutation[i];
        uint32_t src_offset = src_block * block_size;
        uint32_t copy_size = block_size;
        
        // Ultimo blocco può essere più corto
        if (src_offset + copy_size > size) {
            copy_size = size - src_offset;
        }
        
        buffer_append(output, input + src_offset, copy_size);
    }
    
    if (out_map) *out_map = map;
    
    return output;
}

// Unshuffle blocchi
bool structure_unshuffle(const uint8_t *input, uint32_t size,
                        const ShuffleMap *map, uint8_t *output) {
    if (!input || !output || !map) return false;
    
    uint32_t block_size = map->block_size;
    
    // Crea permutazione inversa
    uint32_t *inverse = malloc(map->block_count * sizeof(uint32_t));
    if (!inverse) return false;
    
    for (uint32_t i = 0; i < map->block_count; i++) {
        inverse[map->permutation[i]] = i;
    }
    
    // Ricostruisci ordine originale
    for (uint32_t i = 0; i < map->block_count; i++) {
        uint32_t src_block = inverse[i];
        uint32_t src_offset = src_block * block_size;
        uint32_t dst_offset = i * block_size;
        uint32_t copy_size = block_size;
        
        if (dst_offset + copy_size > size) {
            copy_size = size - dst_offset;
        }
        
        memcpy(output + dst_offset, input + src_offset, copy_size);
    }
    
    free(inverse);
    return true;
}

void shuffle_map_free(ShuffleMap *map) {
    if (!map) return;
    
    if (map->permutation) {
        free(map->permutation);
    }
    
    free(map);
}

// ============================================================================
// OBFUSCATION COMPLETA (combina tutti i metodi)
// ============================================================================

// Obfuscation completa
ObfuscationResult* obfuscate_data(const uint8_t *input, uint32_t size,
                                  const ObfuscationContext *ctx) {
    if (!input || !ctx || size == 0) return NULL;
    
    ObfuscationResult *result = calloc(1, sizeof(ObfuscationResult));
    if (!result) return NULL;
    
    result->original_size = size;
    
    const uint8_t *current_data = input;
    uint32_t current_size = size;
    uint8_t *temp_buffer = NULL;
    
    // 1. POLYMORPHIC ENCODING
    if (ctx->type & OBFUSCATE_POLYMORPHIC) {
        result->poly_seed = ctx->seed;
        Buffer *poly = polymorphic_encode(current_data, current_size, result->poly_seed);
        
        if (poly) {
            temp_buffer = malloc(poly->size);
            if (temp_buffer) {
                memcpy(temp_buffer, poly->data, poly->size);
                current_data = temp_buffer;
                current_size = poly->size;
                result->used_polymorphic = true;
            }
            buffer_free(poly);
        }
    }
    
    // 2. FAKE DATA INJECTION
    if (ctx->type & OBFUSCATE_FAKE_DATA && ctx->fake_data_percent > 0) {
        Buffer *fake = fake_data_inject(current_data, current_size,
                                       ctx->fake_data_percent,
                                       ctx->seed ^ 0x12345678,
                                       &result->fake_map);
        
        if (fake) {
            if (temp_buffer) free(temp_buffer);
            temp_buffer = malloc(fake->size);
            
            if (temp_buffer) {
                memcpy(temp_buffer, fake->data, fake->size);
                current_data = temp_buffer;
                current_size = fake->size;
                result->used_fake_data = true;
            }
            buffer_free(fake);
        }
    }
    
    // 3. STRUCTURE SHUFFLE
    if (ctx->type & OBFUSCATE_STRUCTURE && ctx->shuffle_chunks && current_size > 2048) {
        Buffer *shuffled = structure_shuffle(current_data, current_size,
                                            ctx->seed ^ 0xABCDEF00,
                                            &result->shuffle_map);
        
        if (shuffled) {
            if (temp_buffer) free(temp_buffer);
            temp_buffer = malloc(shuffled->size);
            
            if (temp_buffer) {
                memcpy(temp_buffer, shuffled->data, shuffled->size);
                current_data = temp_buffer;
                current_size = shuffled->size;
                result->used_shuffle = true;
            }
            buffer_free(shuffled);
        }
    }
    
    // Copia risultato finale
    result->data = malloc(current_size);
    if (!result->data) {
        if (temp_buffer) free(temp_buffer);
        free(result);
        return NULL;
    }
    
    memcpy(result->data, current_data, current_size);
    result->size = current_size;
    
    if (temp_buffer) free(temp_buffer);
    
    return result;
}

// Deobfuscation completa (ordine inverso)
bool deobfuscate_data(const uint8_t *input, uint32_t size,
                     const ObfuscationResult *params,
                     uint8_t *output) {
    if (!input || !output || !params) return false;
    
    uint8_t *temp1 = malloc(size * 2);  // Buffer temporaneo ampio
    uint8_t *temp2 = malloc(size * 2);
    
    if (!temp1 || !temp2) {
        free(temp1);
        free(temp2);
        return false;
    }
    
    const uint8_t *current_data = input;
    uint32_t current_size = size;
    
    // 1. UNSHUFFLE (inverso di shuffle)
    if (params->used_shuffle) {
        if (!structure_unshuffle(current_data, current_size, params->shuffle_map, temp1)) {
            free(temp1);
            free(temp2);
            return false;
        }
        current_data = temp1;
    }
    
    // 2. REMOVE FAKE DATA
    if (params->used_fake_data) {
        if (!fake_data_remove(current_data, current_size, params->fake_map, temp2)) {
            free(temp1);
            free(temp2);
            return false;
        }
        current_data = temp2;
        current_size = params->fake_map->real_size;
    }
    
    // 3. POLYMORPHIC DECODE
    if (params->used_polymorphic) {
        if (!polymorphic_decode(current_data, current_size, output)) {
            free(temp1);
            free(temp2);
            return false;
        }
    } else {
        memcpy(output, current_data, params->original_size);
    }
    
    free(temp1);
    free(temp2);
    
    return true;
}

void obfuscation_result_free(ObfuscationResult *result) {
    if (!result) return;
    
    if (result->data) {
        secure_zero(result->data, result->size);
        free(result->data);
    }
    
    if (result->fake_map) {
        fake_data_map_free(result->fake_map);
    }
    
    if (result->shuffle_map) {
        shuffle_map_free(result->shuffle_map);
    }
    
    free(result);
}

// ============================================================================
// STATISTICHE
// ============================================================================

void obfuscation_print_stats(const ObfuscationResult *result) {
    if (!result) return;
    
    printf("Obfuscation stats:\n");
    printf("  Original: %u bytes\n", result->original_size);
    printf("  Obfuscated: %u bytes\n", result->size);
    printf("  Overhead: %.2f%%\n", 
           ((double)result->size / result->original_size - 1.0) * 100);
    printf("  Methods used: ");
    
    if (result->used_polymorphic) printf("Polymorphic ");
    if (result->used_fake_data) printf("FakeData ");
    if (result->used_shuffle) printf("Shuffle ");
    
    printf("\n");
}