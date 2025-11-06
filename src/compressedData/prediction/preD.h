#include "../core/types.h"


// prediction/predictor.c
extern PredictionResult* prediction_encode(const uint8_t *input, uint32_t size);
extern bool prediction_decode(const uint8_t *input, uint32_t size,
                             const PredictionResult *params,
                             uint8_t *output, uint32_t output_size);
extern void prediction_result_free(PredictionResult *result);
extern void prediction_print_stats(const PredictionResult *result, uint32_t original_size);
extern double analyze_entropy(const uint8_t *data, uint32_t size);