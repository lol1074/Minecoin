#include "../core/types.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// ============================================================================
// BURROWS-WHEELER TRANSFORM (BWT)
// ============================================================================

typedef struct {
    uint8_t *data;
    uint32_t index;
} BWTRotation;

// Comparatore per rotazioni
static int bwt_rotation_compare(const void *a, const void *b) {
    const BWTRotation *ra = (const BWTRotation *)a;
    const BWTRotation *rb = (const BWTRotation *)b;
    
    // Confronta rotazioni lessicograficamente
    for (uint32_t i = 0; i < ra->index; i++) {
        if (ra->data[i] != rb->data[i]) {
            return ra->data[i] - rb->data[i];
        }
    }
    return 0;
}

// BWT Forward Transform
bool bwt_encode(const uint8_t *input, uint32_t size, 
                uint8_t *output, uint32_t *primary_index) {
    if (!input || !output || !primary_index || size == 0) return false;
    
    // Limita dimensione per evitare out-of-memory
    if (size > 10 * 1024 * 1024) {  // Max 10MB per blocco BWT
        fprintf(stderr, "BWT: blocco troppo grande (%u bytes)\n", size);
        return false;
    }
    
    // Crea array di rotazioni
    BWTRotation *rotations = malloc(size * sizeof(BWTRotation));
    if (!rotations) return false;
    
    // Crea buffer circolare
    uint8_t *circular = malloc(size * 2);
    if (!circular) {
        free(rotations);
        return false;
    }
    
    memcpy(circular, input, size);
    memcpy(circular + size, input, size);
    
    // Inizializza rotazioni
    for (uint32_t i = 0; i < size; i++) {
        rotations[i].data = circular + i;
        rotations[i].index = size;
    }
    
    // Ordina rotazioni
    qsort(rotations, size, sizeof(BWTRotation), bwt_rotation_compare);
    
    // Estrai ultima colonna e trova primary index
    for (uint32_t i = 0; i < size; i++) {
        output[i] = rotations[i].data[size - 1];
        
        if (rotations[i].data == circular) {
            *primary_index = i;
        }
    }
    
    free(circular);
    free(rotations);
    
    return true;
}

// BWT Inverse Transform
bool bwt_decode(const uint8_t *input, uint32_t size, uint32_t primary_index,
                uint8_t *output) {
    if (!input || !output || size == 0 || primary_index >= size) return false;
    
    // Conta occorrenze caratteri
    uint32_t count[256] = {0};
    for (uint32_t i = 0; i < size; i++) {
        count[input[i]]++;
    }
    
    // Calcola somme cumulative
    uint32_t cumsum[256] = {0};
    for (int i = 1; i < 256; i++) {
        cumsum[i] = cumsum[i-1] + count[i-1];
    }
    
    // Costruisci transformation vector
    uint32_t *T = malloc(size * sizeof(uint32_t));
    if (!T) return false;
    
    for (uint32_t i = 0; i < size; i++) {
        T[cumsum[input[i]]++] = i;
    }
    
    // Ricostruisci stringa originale
    uint32_t idx = primary_index;
    for (uint32_t i = 0; i < size; i++) {
        output[i] = input[idx];
        idx = T[idx];
    }
    
    free(T);
    return true;
}

// ============================================================================
// MOVE-TO-FRONT (MTF) ENCODING
// ============================================================================

// MTF Encode
bool mtf_encode(const uint8_t *input, uint32_t size, uint8_t *output) {
    if (!input || !output || size == 0) return false;
    
    // Inizializza lista simboli (0-255)
    uint8_t symbols[256];
    for (int i = 0; i < 256; i++) {
        symbols[i] = (uint8_t)i;
    }
    
    for (uint32_t i = 0; i < size; i++) {
        uint8_t symbol = input[i];
        
        // Trova posizione nella lista
        uint8_t pos = 0;
        while (symbols[pos] != symbol) {
            pos++;
        }
        
        output[i] = pos;
        
        // Muovi simbolo in testa
        if (pos > 0) {
            memmove(symbols + 1, symbols, pos);
            symbols[0] = symbol;
        }
    }
    
    return true;
}

// MTF Decode
bool mtf_decode(const uint8_t *input, uint32_t size, uint8_t *output) {
    if (!input || !output || size == 0) return false;
    
    // Inizializza lista simboli
    uint8_t symbols[256];
    for (int i = 0; i < 256; i++) {
        symbols[i] = (uint8_t)i;
    }
    
    for (uint32_t i = 0; i < size; i++) {
        uint8_t pos = input[i];
        uint8_t symbol = symbols[pos];
        
        output[i] = symbol;
        
        // Muovi simbolo in testa
        if (pos > 0) {
            memmove(symbols + 1, symbols, pos);
            symbols[0] = symbol;
        }
    }
    
    return true;
}

// ============================================================================
// RUN-LENGTH ENCODING (RLE)
// ============================================================================

// RLE Encode (formato: valore, count)
Buffer* rle_encode(const uint8_t *input, uint32_t size) {
    if (!input || size == 0) return NULL;
    
    Buffer *output = buffer_create(size);
    if (!output) return NULL;
    
    uint32_t i = 0;
    
    while (i < size) {
        uint8_t value = input[i];
        uint32_t count = 1;
        
        // Conta ripetizioni (max 255)
        while (i + count < size && input[i + count] == value && count < 255) {
            count++;
        }
        
        if (count >= 3) {
            // Codifica run: marker (0xFF), valore, count
            uint8_t run[3] = {0xFF, value, (uint8_t)count};
            buffer_append(output, run, 3);
        } else {
            // Run troppo corto, scrivi literal
            for (uint32_t j = 0; j < count; j++) {
                // Se valore è marker, escape con doppio marker
                if (value == 0xFF) {
                    uint8_t escape[2] = {0xFF, 0x00};
                    buffer_append(output, escape, 2);
                } else {
                    buffer_append(output, &value, 1);
                }
            }
        }
        
        i += count;
    }
    
    return output;
}

// RLE Decode
bool rle_decode(const uint8_t *input, uint32_t size, 
                uint8_t *output, uint32_t *output_size) {
    if (!input || !output || !output_size || size == 0) return false;
    
    uint32_t in_pos = 0;
    uint32_t out_pos = 0;
    
    while (in_pos < size) {
        if (input[in_pos] == 0xFF) {
            in_pos++;
            
            if (in_pos >= size) return false;
            
            if (input[in_pos] == 0x00) {
                // Escape: scrivi 0xFF literal
                output[out_pos++] = 0xFF;
                in_pos++;
            } else {
                // Run: valore, count
                uint8_t value = input[in_pos++];
                if (in_pos >= size) return false;
                
                uint8_t count = input[in_pos++];
                
                // Scrivi run
                for (uint8_t i = 0; i < count; i++) {
                    output[out_pos++] = value;
                }
            }
        } else {
            // Literal normale
            output[out_pos++] = input[in_pos++];
        }
    }
    
    *output_size = out_pos;
    return true;
}

// ============================================================================
// PIPELINE COMPLETA PRE-PROCESSING
// ============================================================================

// Forward: BWT -> MTF -> RLE
PreprocessResult* preprocess_encode(const uint8_t *input, uint32_t size) {
    if (!input || size == 0) return NULL;
    
    PreprocessResult *result = calloc(1, sizeof(PreprocessResult));
    if (!result) return NULL;
    
    // Alloca buffer temporanei
    uint8_t *temp1 = malloc(size);
    uint8_t *temp2 = malloc(size);
    
    if (!temp1 || !temp2) {
        free(temp1);
        free(temp2);
        free(result);
        return NULL;
    }
    
    const uint8_t *current_input = input;
    uint32_t current_size = size;
    
    // 1. BWT (solo per blocchi < 10MB)
    if (size <= 10 * 1024 * 1024) {
        if (bwt_encode(current_input, current_size, temp1, &result->bwt_primary_index)) {
            current_input = temp1;
            result->used_bwt = true;
        }
    }
    
    // 2. MTF
    if (mtf_encode(current_input, current_size, temp2)) {
        current_input = temp2;
        result->used_mtf = true;
    }
    
    // 3. RLE
    Buffer *rle_buf = rle_encode(current_input, current_size);
    if (rle_buf && rle_buf->size < current_size) {
        // RLE ha dato beneficio
        result->data = malloc(rle_buf->size);
        if (result->data) {
            memcpy(result->data, rle_buf->data, rle_buf->size);
            result->size = rle_buf->size;
            result->used_rle = true;
        }
        buffer_free(rle_buf);
    } else {
        // RLE non ha migliorato, usa output precedente
        result->data = malloc(current_size);
        if (result->data) {
            memcpy(result->data, current_input, current_size);
            result->size = current_size;
        }
        if (rle_buf) buffer_free(rle_buf);
    }
    
    free(temp1);
    free(temp2);
    
    if (!result->data) {
        free(result);
        return NULL;
    }
    
    return result;
}

// Inverse: RLE -> MTF -> BWT
bool preprocess_decode(const uint8_t *input, uint32_t size,
                       const PreprocessResult *params,
                       uint8_t *output, uint32_t *output_size) {
    if (!input || !output || !output_size || !params) return false;
    
    uint8_t *temp1 = malloc(size * 2);  // Può espandersi con RLE
    uint8_t *temp2 = malloc(size * 2);
    
    if (!temp1 || !temp2) {
        free(temp1);
        free(temp2);
        return false;
    }
    
    const uint8_t *current_input = input;
    uint32_t current_size = size;
    
    // 1. RLE inverse
    if (params->used_rle) {
        uint32_t decoded_size;
        if (!rle_decode(current_input, current_size, temp1, &decoded_size)) {
            free(temp1);
            free(temp2);
            return false;
        }
        current_input = temp1;
        current_size = decoded_size;
    }
    
    // 2. MTF inverse
    if (params->used_mtf) {
        if (!mtf_decode(current_input, current_size, temp2)) {
            free(temp1);
            free(temp2);
            return false;
        }
        current_input = temp2;
    }
    
    // 3. BWT inverse
    if (params->used_bwt) {
        if (!bwt_decode(current_input, current_size, params->bwt_primary_index, output)) {
            free(temp1);
            free(temp2);
            return false;
        }
    } else {
        memcpy(output, current_input, current_size);
    }
    
    *output_size = current_size;
    
    free(temp1);
    free(temp2);
    
    return true;
}

void preprocess_result_free(PreprocessResult *result) {
    if (!result) return;
    
    if (result->data) {
        secure_zero(result->data, result->size);
        free(result->data);
    }
    
    free(result);
}

// ============================================================================
// UTILITY E STATISTICS
// ============================================================================

// Analizza compressibilità dati
double analyze_entropy(const uint8_t *data, uint32_t size) {
    if (!data || size == 0) return 0.0;
    
    uint32_t freq[256] = {0};
    
    // Conta frequenze
    for (uint32_t i = 0; i < size; i++) {
        freq[data[i]]++;
    }
    
    // Calcola entropia Shannon
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / size;
            entropy -= p * (log(p) / log(2.0));
        }
    }
    
    return entropy;
}

// Stampa statistiche preprocessing
void preprocess_print_stats(const PreprocessResult *result, uint32_t original_size) {
    if (!result) return;
    
    printf("Preprocessing stats:\n");
    printf("  Original size: %u bytes\n", original_size);
    printf("  Processed size: %u bytes\n", result->size);
    printf("  Ratio: %.2f%%\n", (double)result->size / original_size * 100);
    printf("  Methods used: ");
    
    if (result->used_bwt) printf("BWT ");
    if (result->used_mtf) printf("MTF ");
    if (result->used_rle) printf("RLE ");
    
    printf("\n");
    
    if (result->used_bwt) {
        printf("  BWT primary index: %u\n", result->bwt_primary_index);
    }
}