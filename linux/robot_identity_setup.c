// linux_robot/robot_identity_setup.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#define IDENTITY_FILE "robot_identity.conf"

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage:\n");
        printf("  %s <DEVICE_ID> <SERIAL_NUMBER>\n\n", argv[0]);
        printf("Example:\n");
        printf("  %s ROBOT_001 RB2026-0001\n", argv[0]);
        return 1;
    }

    const char *device_id = argv[1];
    const char *serial_number = argv[2];

    if (sodium_init() < 0) {
        printf("libsodium initialization failed\n");
        return 1;
    }

    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];

    crypto_sign_keypair(public_key, private_key);

    char public_key_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    char private_key_hex[crypto_sign_SECRETKEYBYTES * 2 + 1];

    sodium_bin2hex(
        public_key_hex,
        sizeof(public_key_hex),
        public_key,
        sizeof(public_key)
    );

    sodium_bin2hex(
        private_key_hex,
        sizeof(private_key_hex),
        private_key,
        sizeof(private_key)
    );

    FILE *file = fopen(IDENTITY_FILE, "w");

    if (file == NULL) {
        perror("Failed to create robot_identity.conf");
        return 1;
    }

    fprintf(file, "DEVICE_ID=%s\n", device_id);
    fprintf(file, "SERIAL_NUMBER=%s\n", serial_number);
    fprintf(file, "PUBLIC_KEY=%s\n", public_key_hex);
    fprintf(file, "PRIVATE_KEY=%s\n", private_key_hex);

    fclose(file);

    printf("Robot identity created successfully.\n");
    printf("Identity file: %s\n", IDENTITY_FILE);
    printf("Device ID: %s\n", device_id);
    printf("Serial Number: %s\n", serial_number);
    printf("\nDo not share robot_identity.conf because it contains the private key.\n");

    return 0;
}