#include "../core/types.h"

// DEVE ESSERE COSÌ:
extern PreprocessResult* preprocess_encode(const uint8_t *input, uint32_t size);
extern bool preprocess_decode(const uint8_t *input, uint32_t size,
                             const PreprocessResult *params,
                             uint8_t *output, uint32_t *output_size);
extern void preprocess_result_free(PreprocessResult *result);
extern void preprocess_print_stats(const PreprocessResult *result, uint32_t original_size);