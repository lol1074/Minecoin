#ifndef OBFUSCATION_H
#define OBFUSCATION_H

#include "../core/types.h" 
#include <stdbool.h>
#include <stdint.h>

// I prototipi usano ora il tipo conosciuto
extern ObfuscationResult* obfuscate_data(const uint8_t *input, uint32_t size, const ObfuscationContext *ctx);
extern bool deobfuscate_data(const uint8_t *input, uint32_t size, const ObfuscationResult *params, uint8_t *output);
extern void obfuscation_result_free(ObfuscationResult *result);
extern void obfuscation_print_stats(const ObfuscationResult *result);

#endif // OBFUSCATION_H