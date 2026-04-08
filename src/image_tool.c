#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include "image_header.h"
#include "hash.h"
#include "ecdsa.h"

#ifndef ECDSA_PRIVATE_KEY
#define ECDSA_PRIVATE_KEY NULL  // Set via command line or env
#endif

void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s create [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --image <file>     Input image file\n");
    fprintf(stderr, "  --output <file>   Output signed image file\n");
    fprintf(stderr, "  --key <file>      Private key file (PEM)\n");
    fprintf(stderr, "  --type <id>       Image type identifier\n");
    fprintf(stderr, "  --hash <algo>     Hash algorithm (sha256, sha384)\n");
    fprintf(stderr, "  --sig <algo>      Signature algorithm (p256, p384)\n");
}

int create_signed_image(const char *image_file, const char *output_file,
                        const char *key_file, uint32_t image_type,
                        uint32_t hash_algo, uint32_t sig_algo) {
    FILE *fp;
    uint8_t *image_data = NULL;
    size_t image_size;
    uint8_t *signed_image = NULL;
    size_t signed_size;
    image_header_t header;
    uint8_t hash_buf[HASH_MAX_DIGEST_SIZE];
    size_t hash_len;
    hash_context_t hash_ctx;
    uint8_t *sig_buf = NULL;
    size_t sig_len = (sig_algo == SIG_ALGO_ECDSA_P256) ? 64 : 96;
    int ret = -1;

    (void)key_file;  // TODO: Use private key for actual signing

    // Read image file
    fp = fopen(image_file, "rb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open image file: %s\n", image_file);
        return -1;
    }
    fseek(fp, 0, SEEK_END);
    image_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    image_data = malloc(image_size);
    if (!image_data) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(fp);
        return -1;
    }
    fread(image_data, 1, image_size, fp);
    fclose(fp);

    // Prepare header
    memset(&header, 0, sizeof(header));
    header.version = 0x00010000;  // 1.0.0
    header.image_type = image_type;
    header.image_length = (uint32_t)image_size;
    header.flags = 0;
    header.timestamp = (uint64_t)time(NULL);
    header.hash_algo = hash_algo;
    header.sig_algo = sig_algo;

    // Calculate hash
    if (hash_init(&hash_ctx, hash_algo) != 0) {
        fprintf(stderr, "Error: Failed to initialize hash context\n");
        goto cleanup;
    }
    hash_update(&hash_ctx, (uint8_t *)&header, IMAGE_HEADER_SIZE);
    hash_update(&hash_ctx, image_data, image_size);
    if (hash_final(&hash_ctx, hash_buf, &hash_len) != 0) {
        fprintf(stderr, "Error: Failed to compute hash\n");
        hash_free(&hash_ctx);
        goto cleanup;
    }
    hash_free(&hash_ctx);

    // Sign hash (placeholder - actual signing would use private key)
    sig_buf = malloc(sig_len);
    if (!sig_buf) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }
    memset(sig_buf, 0, sig_len);  // TODO: Actually sign with private key

    // Create signed image
    signed_size = IMAGE_HEADER_SIZE + image_size + sig_len;
    signed_image = malloc(signed_size);
    if (!signed_image) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        goto cleanup;
    }
    memcpy(signed_image, &header, IMAGE_HEADER_SIZE);
    memcpy(signed_image + IMAGE_HEADER_SIZE, image_data, image_size);
    memcpy(signed_image + IMAGE_HEADER_SIZE + image_size, sig_buf, sig_len);

    // Write output
    fp = fopen(output_file, "wb");
    if (!fp) {
        fprintf(stderr, "Error: Cannot create output file: %s\n", output_file);
        goto cleanup;
    }
    fwrite(signed_image, 1, signed_size, fp);
    fclose(fp);

    printf("Signed image created: %s (%zu bytes)\n", output_file, signed_size);
    printf("  Image: %zu bytes\n", image_size);
    printf("  Hash: %zu bytes (%s)\n", hash_len, hash_algo == HASH_ALGO_SHA256 ? "SHA256" : "SHA384");
    printf("  Signature: %zu bytes\n", sig_len);

    ret = 0;

cleanup:
    free(image_data);
    free(signed_image);
    free(sig_buf);

    return ret;
}

int main(int argc, char *argv[]) {
    const char *prog = argv[0];

    if (argc < 2) {
        print_usage(prog);
        return 1;
    }

    if (strcmp(argv[1], "create") == 0) {
        const char *image_file = NULL;
        const char *output_file = NULL;
        const char *key_file = NULL;
        uint32_t image_type = 0;
        uint32_t hash_algo = HASH_ALGO_SHA256;
        uint32_t sig_algo = SIG_ALGO_ECDSA_P256;

        // Simple argument parsing
        for (int i = 2; i < argc; i++) {
            if (strcmp(argv[i], "--image") == 0 && i + 1 < argc) {
                image_file = argv[++i];
            } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
                output_file = argv[++i];
            } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
                key_file = argv[++i];
            } else if (strcmp(argv[i], "--type") == 0 && i + 1 < argc) {
                image_type = (uint32_t)atoi(argv[++i]);
            } else if (strcmp(argv[i], "--hash") == 0 && i + 1 < argc) {
                if (strcmp(argv[++i], "sha384") == 0) {
                    hash_algo = HASH_ALGO_SHA384;
                }
            } else if (strcmp(argv[i], "--sig") == 0 && i + 1 < argc) {
                if (strcmp(argv[++i], "p384") == 0) {
                    sig_algo = SIG_ALGO_ECDSA_P384;
                }
            }
        }

        if (!image_file || !output_file) {
            fprintf(stderr, "Error: --image and --output are required\n");
            print_usage(prog);
            return 1;
        }

        return create_signed_image(image_file, output_file, key_file,
                                  image_type, hash_algo, sig_algo);
    }

    print_usage(prog);
    return 1;
}
