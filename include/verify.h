#ifndef VERIFY_H
#define VERIFY_H

#include <stddef.h>
#include <stdint.h>

#define VERIFY_SUCCESS           0
#define VERIFY_ERROR_LENGTH     -1
#define VERIFY_ERROR_HEADER     -2
#define VERIFY_ERROR_HASH       -3
#define VERIFY_ERROR_SIGNATURE  -4

int verify_image(const uint8_t *image, size_t image_len);

#endif // VERIFY_H
