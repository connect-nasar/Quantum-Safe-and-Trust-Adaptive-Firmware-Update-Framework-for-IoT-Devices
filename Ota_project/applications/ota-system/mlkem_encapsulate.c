#include <oqs/oqs.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#define PUBLIC_KEY_BYTES OQS_KEM_ml_kem_768_length_public_key
#define CIPHERTEXT_BYTES OQS_KEM_ml_kem_768_length_ciphertext
#define SHARED_SECRET_BYTES OQS_KEM_ml_kem_768_length_shared_secret

static int read_exact(const char *path, uint8_t *buffer, size_t length)
{
    FILE *file = fopen(path, "rb");
    int result = 0;
    if (file != NULL && fread(buffer, 1, length, file) == length) {
        result = fgetc(file) == EOF;
    }
    if (file != NULL) {
        fclose(file);
    }
    return result;
}

static int write_exact(const char *path, const uint8_t *buffer, size_t length)
{
    FILE *file = fopen(path, "wb");
    int result = file != NULL && fwrite(buffer, 1, length, file) == length;
    if (file != NULL) {
        result = result && fclose(file) == 0;
    }
    return result;
}

int main(int argc, char **argv)
{
    uint8_t public_key[PUBLIC_KEY_BYTES];
    uint8_t ciphertext[CIPHERTEXT_BYTES];
    uint8_t shared_secret[SHARED_SECRET_BYTES];

    if (argc != 4 || !read_exact(argv[1], public_key, sizeof(public_key))) {
        fprintf(stderr, "Usage: mlkem_encapsulate DEVICE_PUBLIC_KEY OUT_CIPHERTEXT OUT_SECRET\n");
        return 2;
    }

    OQS_init();
    OQS_STATUS status = OQS_KEM_ml_kem_768_encaps(ciphertext, shared_secret, public_key);
    if (status != OQS_SUCCESS ||
        !write_exact(argv[2], ciphertext, sizeof(ciphertext)) ||
        !write_exact(argv[3], shared_secret, sizeof(shared_secret))) {
        fprintf(stderr, "ML-KEM encapsulation failed\n");
        OQS_destroy();
        return 1;
    }

    OQS_destroy();
    return 0;
}
