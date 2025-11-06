#include "../core/types.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

// ============================================================================
// CONTEXT MODELING
// ============================================================================

#define CONTEXT_ORDER 4        // Order-4 context (guarda 4 byte precedenti)
#define CONTEXT_SIZE (1 << 16) // 64K contexts
#define MAX_FREQ 1024

typedef struct {
    uint16_t freq[256];        // Frequenze simboli
    uint16_t total;            // Totale occorrenze
    uint8_t recent[8];         // Ultimi simboli visti
    uint8_t recent_count;
} Context;

typedef struct {
    Context *contexts;
    uint32_t num_contexts;
    uint8_t history[CONTEXT_ORDER];
    uint32_t history_pos;
} ContextModel;

// Hash per context
static inline uint32_t context_hash(const uint8_t *data, int order) {
    uint32_t h = 0;
    for (int i = 0; i < order; i++) {
        h = (h * 31) + data[i];
    }
    return h % CONTEXT_SIZE;
}

// Crea context model
ContextModel* context_model_create(void) {
    ContextModel *cm = calloc(1, sizeof(ContextModel));
    if (!cm) return NULL;
    
    cm->contexts = calloc(CONTEXT_SIZE, sizeof(Context));
    if (!cm->contexts) {
        free(cm);
        return NULL;
    }
    
    cm->num_contexts = CONTEXT_SIZE;
    cm->history_pos = 0;
    
    // Inizializza contexts con distribuzione uniforme
    for (uint32_t i = 0; i < CONTEXT_SIZE; i++) {
        for (int j = 0; j < 256; j++) {
            cm->contexts[i].freq[j] = 1;
        }
        cm->contexts[i].total = 256;
    }
    
    return cm;
}

void context_model_free(ContextModel *cm) {
    if (!cm) return;
    free(cm->contexts);
    free(cm);
}

// Ottieni context corrente
Context* context_model_get(ContextModel *cm) {
    uint32_t hash = context_hash(cm->history, CONTEXT_ORDER);
    return &cm->contexts[hash];
}

// Aggiorna model con nuovo simbolo
void context_model_update(ContextModel *cm, uint8_t symbol) {
    Context *ctx = context_model_get(cm);
    
    // Incrementa frequenza
    if (ctx->freq[symbol] < MAX_FREQ) {
        ctx->freq[symbol]++;
        ctx->total++;
    } else {
        // Scala frequenze se raggiunto max
        for (int i = 0; i < 256; i++) {
            ctx->freq[i] = (ctx->freq[i] + 1) / 2;
        }
        ctx->total = 0;
        for (int i = 0; i < 256; i++) {
            ctx->total += ctx->freq[i];
        }
    }
    
    // Aggiorna recent symbols
    if (ctx->recent_count < 8) {
        ctx->recent[ctx->recent_count++] = symbol;
    } else {
        memmove(ctx->recent, ctx->recent + 1, 7);
        ctx->recent[7] = symbol;
    }
    
    // Aggiorna history
    memmove(cm->history, cm->history + 1, CONTEXT_ORDER - 1);
    cm->history[CONTEXT_ORDER - 1] = symbol;
}

// Predici prossimo simbolo (per encoding differenziale)
uint8_t context_model_predict(ContextModel *cm) {
    Context *ctx = context_model_get(cm);
    
    // Trova simbolo più probabile
    uint16_t max_freq = 0;
    uint8_t predicted = 0;
    
    for (int i = 0; i < 256; i++) {
        if (ctx->freq[i] > max_freq) {
            max_freq = ctx->freq[i];
            predicted = (uint8_t)i;
        }
    }
    
    // Se abbiamo recent symbols, usa ultimo come fallback
    if (ctx->recent_count > 0 && max_freq < 10) {
        predicted = ctx->recent[ctx->recent_count - 1];
    }
    
    return predicted;
}

// ============================================================================
// DELTA ENCODING
// ============================================================================

// Delta encoding semplice (differenza tra byte consecutivi)
Buffer* delta_encode_simple(const uint8_t *input, uint32_t size) {
    if (!input || size == 0) return NULL;
    
    Buffer *output = buffer_create(size);
    if (!output) return NULL;
    
    // Primo byte literal
    buffer_append(output, &input[0], 1);
    
    // Successivi come delta
    for (uint32_t i = 1; i < size; i++) {
        uint8_t delta = input[i] - input[i-1];
        buffer_append(output, &delta, 1);
    }
    
    return output;
}

// Delta decode semplice
bool delta_decode_simple(const uint8_t *input, uint32_t size, uint8_t *output) {
    if (!input || !output || size == 0) return false;
    
    output[0] = input[0];
    
    for (uint32_t i = 1; i < size; i++) {
        output[i] = output[i-1] + input[i];
    }
    
    return true;
}

// Delta encoding con stride (per dati strutturati)
Buffer* delta_encode_stride(const uint8_t *input, uint32_t size, int stride) {
    if (!input || size == 0 || stride <= 0 || stride > 16) return NULL;
    
    Buffer *output = buffer_create(size);
    if (!output) return NULL;
    
    // Primi stride bytes literal
    buffer_append(output, input, stride);
    
    // Successivi come delta rispetto a stride precedente
    for (uint32_t i = stride; i < size; i++) {
        uint8_t delta = input[i] - input[i - stride];
        buffer_append(output, &delta, 1);
    }
    
    return output;
}

// Delta decode con stride
bool delta_decode_stride(const uint8_t *input, uint32_t size, int stride, uint8_t *output) {
    if (!input || !output || size == 0 || stride <= 0) return false;
    
    memcpy(output, input, stride);
    
    for (uint32_t i = stride; i < size; i++) {
        output[i] = output[i - stride] + input[i];
    }
    
    return true;
}

// ============================================================================
// PREDICTION ENCODING (Context-based)
// ============================================================================

// Encoding con prediction
PredictionResult* prediction_encode(const uint8_t *input, uint32_t size) {
    if (!input || size == 0) return NULL;
    
    PredictionResult *result = calloc(1, sizeof(PredictionResult));
    if (!result) return NULL;
    
    // Analizza dati per scegliere strategia
    double entropy = analyze_entropy(input, size);
    
    Buffer *output = buffer_create(size);
    if (!output) {
        free(result);
        return NULL;
    }
    
    // Se entropia alta (> 7 bit), dati già random/compressi
    if (entropy > 7.0) {
        // Nessun preprocessing aiuta
        buffer_append(output, input, size);
        result->used_context = false;
        result->used_delta = false;
    }
    // Se entropia bassa (< 5 bit), usa context model
    else if (entropy < 5.0) {
        ContextModel *cm = context_model_create();
        if (cm) {
            // Encoding predittivo
            for (uint32_t i = 0; i < size; i++) {
                uint8_t predicted = context_model_predict(cm);
                uint8_t delta = input[i] - predicted;
                buffer_append(output, &delta, 1);
                context_model_update(cm, input[i]);
            }
            
            context_model_free(cm);
            result->used_context = true;
        }
    }
    // Entropia media, prova delta encoding
    else {
        // Prova diversi stride
        int best_stride = -1;
        size_t best_size = size;
        
        for (int stride = 1; stride <= 4; stride *= 2) {
            Buffer *test = delta_encode_stride(input, size, stride);
            if (test && test->size < best_size) {
                best_size = test->size;
                best_stride = stride;
            }
            if (test) buffer_free(test);
        }
        
        if (best_stride > 0) {
            Buffer *delta = delta_encode_stride(input, size, best_stride);
            if (delta) {
                buffer_append(output, delta->data, delta->size);
                buffer_free(delta);
                result->stride = best_stride;
                result->used_delta = true;
            }
        } else {
            buffer_append(output, input, size);
        }
    }
    
    result->data = malloc(output->size);
    if (result->data) {
        memcpy(result->data, output->data, output->size);
        result->size = output->size;
    }
    
    buffer_free(output);
    
    if (!result->data) {
        free(result);
        return NULL;
    }
    
    return result;
}

// Decoding con prediction
bool prediction_decode(const uint8_t *input, uint32_t size,
                      const PredictionResult *params,
                      uint8_t *output, uint32_t output_size) {
    if (!input || !output || !params || size == 0) return false;
    
    // Context model decoding
    if (params->used_context) {
        ContextModel *cm = context_model_create();
        if (!cm) return false;
        
        for (uint32_t i = 0; i < size; i++) {
            uint8_t predicted = context_model_predict(cm);
            output[i] = predicted + input[i];
            context_model_update(cm, output[i]);
        }
        
        context_model_free(cm);
        return true;
    }
    
    // Delta decoding
    if (params->used_delta && params->stride > 0) {
        return delta_decode_stride(input, size, params->stride, output);
    }
    
    // Nessun encoding
    if (size == output_size) {
        memcpy(output, input, size);
        return true;
    }
    
    return false;
}

void prediction_result_free(PredictionResult *result) {
    if (!result) return;
    
    if (result->data) {
        secure_zero(result->data, result->size);
        free(result->data);
    }
    
    free(result);
}

// ============================================================================
// ADAPTIVE PREDICTOR (combina più metodi)
// ============================================================================

typedef struct {
    uint8_t method;       // 0=none, 1=simple, 2=stride, 3=context
    int stride;
    double gain;          // Quanto ha migliorato
} AdaptiveChoice;

AdaptiveChoice adaptive_analyze(const uint8_t *input, uint32_t size) {
    AdaptiveChoice choice = {0, 1, 0.0};
    
    if (!input || size < 1024) return choice;
    
    // Campiona blocco iniziale (primi 4KB)
    uint32_t sample_size = (size > 4096) ? 4096 : size;
    
    double original_entropy = analyze_entropy(input, sample_size);
    
    // Prova delta semplice
    Buffer *delta_simple = delta_encode_simple(input, sample_size);
    if (delta_simple) {
        double delta_entropy = analyze_entropy(delta_simple->data, delta_simple->size);
        double gain = original_entropy - delta_entropy;
        
        if (gain > choice.gain) {
            choice.method = 1;
            choice.stride = 1;
            choice.gain = gain;
        }
        
        buffer_free(delta_simple);
    }
    
    // Prova stride encoding
    for (int stride = 2; stride <= 4; stride++) {
        Buffer *delta_stride = delta_encode_stride(input, sample_size, stride);
        if (delta_stride) {
            double stride_entropy = analyze_entropy(delta_stride->data, delta_stride->size);
            double gain = original_entropy - stride_entropy;
            
            if (gain > choice.gain) {
                choice.method = 2;
                choice.stride = stride;
                choice.gain = gain;
            }
            
            buffer_free(delta_stride);
        }
    }
    
    // Se guadagno significativo (> 0.5 bit), usa method
    if (choice.gain < 0.5) {
        choice.method = 0;  // No prediction
    }
    
    return choice;
}

// ============================================================================
// STATISTICHE
// ============================================================================

void prediction_print_stats(const PredictionResult *result, uint32_t original_size) {
    if (!result) return;
    
    printf("Prediction stats:\n");
    printf("  Original: %u bytes\n", original_size);
    printf("  Predicted: %u bytes\n", result->size);
    printf("  Ratio: %.2f%%\n", (double)result->size / original_size * 100);
    printf("  Methods: ");
    
    if (result->used_context) printf("Context ");
    if (result->used_delta) printf("Delta(stride=%d) ", result->stride);
    if (!result->used_context && !result->used_delta) printf("None");
    
    printf("\n");
}