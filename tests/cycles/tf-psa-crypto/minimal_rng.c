#include <stdlib.h>
#include <time.h>

#include "psa/crypto.h"

psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t *context,
    uint8_t *output, size_t output_size, size_t *output_length) {

    (void)context;
    size_t i;

    for (i = 0; i < output_size; i++) {
        output[i] = (uint8_t)rand();
    }

    *output_length = output_size;

    return PSA_SUCCESS;
}
