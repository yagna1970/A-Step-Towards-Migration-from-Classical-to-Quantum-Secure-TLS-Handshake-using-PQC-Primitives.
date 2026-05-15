#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include "params.h"
#include "indcpa.h"

#define PK_FILE "server_pk.bin"
#define CT_FILE "client_ct.bin"

#define SESSION_KEY_LEN 32

struct timeval start_time;

void start_timer() {
    gettimeofday(&start_time, NULL);
}

void print_elapsed_time() {

    struct timeval current;

    gettimeofday(&current, NULL);

    double elapsed =
        (current.tv_sec - start_time.tv_sec) +
        (current.tv_usec - start_time.tv_usec) / 1000000.0;

    printf("[%.6f sec] ", elapsed);
}

void randombytes(uint8_t *buf, size_t len) {

    for (size_t i = 0; i < len; i++)
        buf[i] = rand() % 256;
}

void print_hex(uint8_t *data, int len) {

    for (int i = 0; i < 16 && i < len; i++)
        printf("%02X ", data[i]);

    printf("...\n");
}

int write_file(const char *name,
               uint8_t *data,
               size_t len) {

    FILE *f = fopen(name, "wb");

    if (!f) return -1;

    fwrite(data, 1, len, f);

    fclose(f);

    return 0;
}

int read_file(const char *name,
              uint8_t *data,
              size_t len) {

    FILE *f = fopen(name, "rb");

    if (!f) return -1;

    size_t r = fread(data, 1, len, f);

    fclose(f);

    return (r == len) ? 0 : -1;
}

void derive_key(uint8_t *key,
                uint8_t *secret,
                size_t len) {

    for (int i = 0; i < SESSION_KEY_LEN; i++)
        key[i] = 0;

    for (size_t i = 0; i < len; i++)
        key[i % SESSION_KEY_LEN] ^= secret[i];
}

int main() {

    srand(time(NULL));

    start_timer();

    uint8_t pk[KYBER_INDCPA_PUBLICKEYBYTES];
    uint8_t sk[KYBER_INDCPA_SECRETKEYBYTES];
    uint8_t ct[KYBER_INDCPA_BYTES];
    uint8_t shared[KYBER_INDCPA_MSGBYTES];
    uint8_t session_key[SESSION_KEY_LEN];

    printf("\n===== PQC TLS SERVER =====\n");

    print_elapsed_time();
    printf("[STEP 1] ClientHello received\n");

    print_elapsed_time();
    printf("[STEP 2] Generating Kyber keypair...\n");

    indcpa_keypair(pk, sk);

    printf("Public Key (%d bytes): ",
           KYBER_INDCPA_PUBLICKEYBYTES);

    print_hex(pk, KYBER_INDCPA_PUBLICKEYBYTES);

    printf("Secret Key (%d bytes): [hidden]\n",
           KYBER_INDCPA_SECRETKEYBYTES);

    print_elapsed_time();
    printf("[STEP 3] Sending public key to client\n");

    write_file(PK_FILE,
               pk,
               KYBER_INDCPA_PUBLICKEYBYTES);

    print_elapsed_time();
    printf("[STEP 4] Waiting for ciphertext...\n");

    while (read_file(CT_FILE,
           ct,
           KYBER_INDCPA_BYTES) != 0);

    printf("Ciphertext received (%d bytes)\n",
           KYBER_INDCPA_BYTES);

    print_elapsed_time();
    printf("[STEP 5] Decrypting ciphertext...\n");

    indcpa_dec(shared, ct, sk);

    printf("Shared Secret (%d bytes): ",
           KYBER_INDCPA_MSGBYTES);

    print_hex(shared, KYBER_INDCPA_MSGBYTES);

    print_elapsed_time();
    printf("[STEP 6] Deriving session key...\n");

    derive_key(session_key,
               shared,
               KYBER_INDCPA_MSGBYTES);

    printf("Session Key: ");

    print_hex(session_key, SESSION_KEY_LEN);

    print_elapsed_time();
    printf("[STEP 7] Handshake complete\n");

    printf("\nKey Sizes:\n");

    printf("Public Key   : %d bytes\n",
           KYBER_INDCPA_PUBLICKEYBYTES);

    printf("Secret Key   : %d bytes\n",
           KYBER_INDCPA_SECRETKEYBYTES);

    printf("Ciphertext   : %d bytes\n",
           KYBER_INDCPA_BYTES);

    printf("Shared Secret: %d bytes\n",
           KYBER_INDCPA_MSGBYTES);

    printf("\n===== SERVER DONE =====\n");

    remove(PK_FILE);
    remove(CT_FILE);

    return 0;
}