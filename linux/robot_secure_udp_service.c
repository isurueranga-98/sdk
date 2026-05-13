// linux_robot/robot_secure_udp_service.c
//
// Secure UDP robot service:
//   1. Plain signed discovery on UDP 5005.
//   2. Signed key exchange on UDP 5006.
//   3. Encrypted/authenticated robot data on UDP 5006.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sodium.h>

#define IDENTITY_FILE "robot_identity.conf"

#define DISCOVERY_PORT 5005
#define DATA_PORT 5006

#define SHM_NAME "/robot_shared_memory"
#define SHM_SIZE 1024

#define MAGIC_SIZE 8
#define DEVICE_ID_SIZE 32
#define SERIAL_SIZE 32
#define IP_SIZE 32
#define MESSAGE_SIZE 256

#define CHUNK_SIZE 1200
#define WINDOW_SIZE 32
#define ACK_TIMEOUT_MS 100
#define MAX_RETRIES 200
#define UDP_BUFFER_SIZE (4 * 1024 * 1024)
#define MAX_FILE_SIZE (100ULL * 1024ULL * 1024ULL)
#define DOWNLOAD_DIR "downloads"
#define FILE_NAME_SIZE 128
#define FILE_PATH_SIZE 256
#define FILE_MESSAGE_SIZE 128
#define ACK_MESSAGE_SIZE 64
#define MAX_MISSING_LIST 256
#define FILE_PACKET_MAGIC "RFILE"
#define MAX_FILE_PLAINTEXT_SIZE 1400
#define MAX_FILE_CIPHERTEXT_SIZE \
    (MAX_FILE_PLAINTEXT_SIZE + crypto_aead_xchacha20poly1305_ietf_ABYTES)

#define DISCOVERY_REQUEST_MAGIC "RDISCOV"
#define DISCOVERY_RESPONSE_MAGIC "RRESPON"
#define KX_REQUEST_MAGIC "RKXREQ"
#define KX_RESPONSE_MAGIC "RKXRES"
#define ENCRYPTED_DATA_REQUEST_MAGIC "RENCQ"
#define ENCRYPTED_DATA_RESPONSE_MAGIC "RENCR"
#define DATA_REQUEST_MAGIC "EDATAQ"
#define DATA_RESPONSE_MAGIC "EDATAR"

#define FRESHNESS_WINDOW_SECONDS 10

enum {
    PACKET_TYPE_FILE_META = 1,
    PACKET_TYPE_FILE_META_ACK = 2,
    PACKET_TYPE_FILE_CHUNK = 3,
    PACKET_TYPE_FILE_CHUNK_ACK = 4,
    PACKET_TYPE_FILE_STATUS_REQUEST = 5,
    PACKET_TYPE_FILE_STATUS_RESPONSE = 6,
    PACKET_TYPE_FILE_COMPLETE_REQUEST = 7,
    PACKET_TYPE_FILE_COMPLETE_RESPONSE = 8,
    PACKET_TYPE_FILE_TRANSFER_FAILED = 9
};

#pragma pack(push, 1)

typedef struct {
    int32_t counter;
    float battery_level;
    float temperature;
    char message[MESSAGE_SIZE];
} RobotSharedData;

typedef struct {
    char magic[MAGIC_SIZE];
    uint64_t challenge_nonce;
    uint64_t timestamp;
} DiscoveryRequestPacket;

typedef struct {
    char magic[MAGIC_SIZE];
    char device_id[DEVICE_ID_SIZE];
    char serial_number[SERIAL_SIZE];
    char ip_address[IP_SIZE];
    uint16_t service_port;
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    uint64_t challenge_nonce;
    uint64_t timestamp;
} DiscoveryResponseBody;

typedef struct {
    DiscoveryResponseBody body;
    unsigned char signature[crypto_sign_BYTES];
} DiscoveryResponsePacket;

typedef struct {
    char magic[MAGIC_SIZE];
    char device_id[DEVICE_ID_SIZE];
    char serial_number[SERIAL_SIZE];
    unsigned char client_kx_public_key[crypto_kx_PUBLICKEYBYTES];
    uint64_t challenge_nonce;
    uint64_t timestamp;
} KeyExchangeRequestPacket;

typedef struct {
    char magic[MAGIC_SIZE];
    char device_id[DEVICE_ID_SIZE];
    char serial_number[SERIAL_SIZE];
    unsigned char client_kx_public_key[crypto_kx_PUBLICKEYBYTES];
    unsigned char server_kx_public_key[crypto_kx_PUBLICKEYBYTES];
    uint64_t challenge_nonce;
    uint64_t timestamp;
} KeyExchangeResponseBody;

typedef struct {
    KeyExchangeResponseBody body;
    unsigned char signature[crypto_sign_BYTES];
} KeyExchangeResponsePacket;

typedef struct {
    char magic[MAGIC_SIZE];
    char device_id[DEVICE_ID_SIZE];
    char serial_number[SERIAL_SIZE];
    uint32_t request_sequence;
    uint64_t challenge_nonce;
    uint64_t timestamp;
} EncryptedDataRequestBody;

typedef struct {
    char magic[MAGIC_SIZE];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char ciphertext[
        sizeof(EncryptedDataRequestBody) +
        crypto_aead_xchacha20poly1305_ietf_ABYTES
    ];
} EncryptedDataRequestPacket;

typedef struct {
    char magic[MAGIC_SIZE];
    char device_id[DEVICE_ID_SIZE];
    char serial_number[SERIAL_SIZE];
    uint32_t response_sequence;
    uint64_t challenge_nonce;
    uint64_t timestamp;
    int32_t counter;
    float battery_level;
    float temperature;
    char message[MESSAGE_SIZE];
} EncryptedDataResponseBody;

typedef struct {
    char magic[MAGIC_SIZE];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char ciphertext[
        sizeof(EncryptedDataResponseBody) +
        crypto_aead_xchacha20poly1305_ietf_ABYTES
    ];
} EncryptedDataResponsePacket;

typedef struct {
    char magic[MAGIC_SIZE];
    uint32_t packet_type;
    uint64_t transfer_id;
    uint32_t sequence_number;
    uint64_t timestamp;
    char file_name[FILE_NAME_SIZE];
    uint64_t file_size;
    uint32_t chunk_size;
    uint32_t total_chunks;
    unsigned char file_sha256[crypto_hash_sha256_BYTES];
} FileMetaPlain;

typedef struct {
    char magic[MAGIC_SIZE];
    uint32_t packet_type;
    uint64_t transfer_id;
    uint32_t sequence_number;
    uint64_t timestamp;
    int32_t accepted;
    char message[FILE_MESSAGE_SIZE];
} FileMetaAckPlain;

typedef struct {
    char magic[MAGIC_SIZE];
    uint32_t packet_type;
    uint64_t transfer_id;
    uint32_t sequence_number;
    uint64_t timestamp;
    uint32_t chunk_index;
    uint32_t chunk_size;
    uint64_t offset;
    unsigned char data[CHUNK_SIZE];
} FileChunkPlain;

typedef struct {
    char magic[MAGIC_SIZE];
    uint32_t packet_type;
    uint64_t transfer_id;
    uint32_t sequence_number;
    uint64_t timestamp;
    uint32_t chunk_index;
    int32_t status;
    char message[ACK_MESSAGE_SIZE];
} FileChunkAckPlain;

typedef struct {
    char magic[MAGIC_SIZE];
    uint32_t packet_type;
    uint64_t transfer_id;
    uint32_t sequence_number;
    uint64_t timestamp;
} FileStatusRequestPlain;

typedef struct {
    char magic[MAGIC_SIZE];
    uint32_t packet_type;
    uint64_t transfer_id;
    uint32_t sequence_number;
    uint64_t timestamp;
    uint32_t total_chunks;
    uint32_t received_chunks;
    uint32_t missing_count;
    uint32_t missing_indices[MAX_MISSING_LIST];
} FileStatusResponsePlain;

typedef struct {
    char magic[MAGIC_SIZE];
    uint32_t packet_type;
    uint64_t transfer_id;
    uint32_t sequence_number;
    uint64_t timestamp;
} FileCompleteRequestPlain;

typedef struct {
    char magic[MAGIC_SIZE];
    uint32_t packet_type;
    uint64_t transfer_id;
    uint32_t sequence_number;
    uint64_t timestamp;
    int32_t success;
    char final_file_path[FILE_PATH_SIZE];
    unsigned char computed_sha256[crypto_hash_sha256_BYTES];
    char message[FILE_MESSAGE_SIZE];
} FileCompleteResponsePlain;

typedef struct {
    char magic[MAGIC_SIZE];
    uint32_t packet_type;
    uint64_t transfer_id;
    uint32_t sequence_number;
    uint64_t timestamp;
    int32_t error_code;
    char message[FILE_MESSAGE_SIZE];
} FileTransferFailedPlain;

typedef struct {
    char magic[MAGIC_SIZE];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    uint32_t ciphertext_len;
    unsigned char ciphertext[MAX_FILE_CIPHERTEXT_SIZE];
} EncryptedFilePacket;

#pragma pack(pop)

typedef struct {
    char device_id[DEVICE_ID_SIZE];
    char serial_number[SERIAL_SIZE];
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];
} RobotIdentity;

typedef struct {
    int active;
    struct sockaddr_in client_addr;
    unsigned char client_kx_public_key[crypto_kx_PUBLICKEYBYTES];
    unsigned char server_kx_public_key[crypto_kx_PUBLICKEYBYTES];
    unsigned char server_kx_private_key[crypto_kx_SECRETKEYBYTES];
    unsigned char rx_key[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx_key[crypto_kx_SESSIONKEYBYTES];
    uint32_t last_request_sequence;
    uint32_t next_response_sequence;
} SecureSession;

typedef struct {
    int active;
    int complete;
    uint64_t transfer_id;
    char file_name[FILE_NAME_SIZE];
    char part_path[FILE_PATH_SIZE];
    char final_path[FILE_PATH_SIZE];
    uint64_t file_size;
    uint32_t chunk_size;
    uint32_t total_chunks;
    uint32_t received_chunks;
    unsigned char expected_sha256[crypto_hash_sha256_BYTES];
    unsigned char *received_bitmap;
    FILE *file;
} FileTransferState;

static int hex_to_bytes(const char *hex, unsigned char *output, size_t output_size) {
    size_t hex_len = strlen(hex);

    if (hex_len != output_size * 2) {
        return -1;
    }

    if (sodium_hex2bin(output, output_size, hex, hex_len, NULL, NULL, NULL) != 0) {
        return -1;
    }

    return 0;
}

static void remove_newline(char *text) {
    text[strcspn(text, "\r\n")] = '\0';
}

static int is_timestamp_fresh(uint64_t packet_timestamp) {
    uint64_t now = (uint64_t)time(NULL);

    if (packet_timestamp + FRESHNESS_WINDOW_SECONDS < now) {
        return 0;
    }

    if (packet_timestamp > now + FRESHNESS_WINDOW_SECONDS) {
        return 0;
    }

    return 1;
}

static void copy_text(char *destination, size_t destination_size, const char *source) {
    if (destination_size == 0) {
        return;
    }

    snprintf(destination, destination_size, "%s", source);
}

static int has_onnx_extension(const char *file_name) {
    size_t length = strlen(file_name);

    if (length < 5) {
        return 0;
    }

    return strcmp(file_name + length - 5, ".onnx") == 0;
}

static int sanitize_filename(const char *file_name) {
    if (file_name == NULL || file_name[0] == '\0') {
        return 0;
    }

    if (strstr(file_name, "../") != NULL ||
        strstr(file_name, "..\\") != NULL ||
        strchr(file_name, '/') != NULL ||
        strchr(file_name, '\\') != NULL ||
        strchr(file_name, ':') != NULL) {
        return 0;
    }

    return has_onnx_extension(file_name);
}

static int create_downloads_directory(void) {
    if (mkdir(DOWNLOAD_DIR, 0700) == 0) {
        return 0;
    }

    if (errno == EEXIST) {
        struct stat st;

        if (stat(DOWNLOAD_DIR, &st) == 0 && S_ISDIR(st.st_mode)) {
            return 0;
        }
    }

    return -1;
}

static int compute_file_sha256(const char *path, unsigned char hash[crypto_hash_sha256_BYTES]) {
    FILE *file = fopen(path, "rb");

    if (file == NULL) {
        return -1;
    }

    crypto_hash_sha256_state state;
    unsigned char buffer[4096];
    size_t read_count;

    crypto_hash_sha256_init(&state);

    while ((read_count = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        crypto_hash_sha256_update(&state, buffer, read_count);
    }

    if (ferror(file)) {
        fclose(file);
        return -1;
    }

    crypto_hash_sha256_final(&state, hash);
    fclose(file);
    return 0;
}

static void cleanup_file_transfer(FileTransferState *transfer) {
    if (transfer->file != NULL) {
        fclose(transfer->file);
        transfer->file = NULL;
    }

    free(transfer->received_bitmap);
    transfer->received_bitmap = NULL;
    memset(transfer, 0, sizeof(*transfer));
}

static int encrypt_packet(
    const SecureSession *session,
    const void *plain,
    size_t plain_len,
    EncryptedFilePacket *packet,
    size_t *packet_len
) {
    unsigned long long encrypted_len = 0;

    if (plain_len > MAX_FILE_PLAINTEXT_SIZE) {
        return -1;
    }

    memset(packet, 0, sizeof(*packet));
    copy_text(packet->magic, MAGIC_SIZE, FILE_PACKET_MAGIC);
    randombytes_buf(packet->nonce, sizeof(packet->nonce));

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            packet->ciphertext,
            &encrypted_len,
            plain,
            plain_len,
            NULL,
            0,
            NULL,
            packet->nonce,
            session->tx_key
        ) != 0) {
        return -1;
    }

    packet->ciphertext_len = (uint32_t)encrypted_len;
    *packet_len = MAGIC_SIZE + sizeof(packet->nonce) +
                  sizeof(packet->ciphertext_len) + packet->ciphertext_len;
    return 0;
}

static int decrypt_packet(
    const SecureSession *session,
    const EncryptedFilePacket *packet,
    size_t packet_len,
    void *plain,
    size_t plain_capacity,
    size_t *plain_len
) {
    unsigned long long decrypted_len = 0;
    size_t header_len = MAGIC_SIZE + sizeof(packet->nonce) +
                        sizeof(packet->ciphertext_len);

    if (packet_len < header_len ||
        strncmp(packet->magic, FILE_PACKET_MAGIC, MAGIC_SIZE) != 0 ||
        packet->ciphertext_len > MAX_FILE_CIPHERTEXT_SIZE ||
        packet_len != header_len + packet->ciphertext_len) {
        return -1;
    }

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plain,
            &decrypted_len,
            NULL,
            packet->ciphertext,
            packet->ciphertext_len,
            NULL,
            0,
            packet->nonce,
            session->rx_key
        ) != 0) {
        return -1;
    }

    if (decrypted_len > plain_capacity) {
        return -1;
    }

    *plain_len = (size_t)decrypted_len;
    return 0;
}

static int send_encrypted_packet(
    int data_sock,
    const struct sockaddr_in *client_addr,
    socklen_t client_len,
    const SecureSession *session,
    const void *plain,
    size_t plain_len
) {
    EncryptedFilePacket packet;
    size_t packet_len = 0;

    if (encrypt_packet(session, plain, plain_len, &packet, &packet_len) != 0) {
        return -1;
    }

    if (sendto(
            data_sock,
            &packet,
            packet_len,
            0,
            (const struct sockaddr *)client_addr,
            client_len
        ) < 0) {
        return -1;
    }

    return 0;
}

static int load_identity(RobotIdentity *identity) {
    FILE *file = fopen(IDENTITY_FILE, "r");

    if (file == NULL) {
        printf("Cannot open %s\n", IDENTITY_FILE);
        printf("Run robot_identity_setup first.\n");
        return -1;
    }

    char line[512];
    char public_key_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1] = {0};
    char private_key_hex[crypto_sign_SECRETKEYBYTES * 2 + 1] = {0};

    memset(identity, 0, sizeof(RobotIdentity));

    while (fgets(line, sizeof(line), file)) {
        remove_newline(line);

        if (strncmp(line, "DEVICE_ID=", 10) == 0) {
            strncpy(identity->device_id, line + 10, DEVICE_ID_SIZE - 1);
        } else if (strncmp(line, "SERIAL_NUMBER=", 14) == 0) {
            strncpy(identity->serial_number, line + 14, SERIAL_SIZE - 1);
        } else if (strncmp(line, "PUBLIC_KEY=", 11) == 0) {
            strncpy(public_key_hex, line + 11, sizeof(public_key_hex) - 1);
        } else if (strncmp(line, "PRIVATE_KEY=", 12) == 0) {
            strncpy(private_key_hex, line + 12, sizeof(private_key_hex) - 1);
        }
    }

    fclose(file);

    if (strlen(identity->device_id) == 0 ||
        strlen(identity->serial_number) == 0 ||
        strlen(public_key_hex) == 0 ||
        strlen(private_key_hex) == 0) {
        printf("Invalid identity file\n");
        return -1;
    }

    if (hex_to_bytes(public_key_hex, identity->public_key, sizeof(identity->public_key)) != 0) {
        printf("Invalid public key in identity file\n");
        return -1;
    }

    if (hex_to_bytes(private_key_hex, identity->private_key, sizeof(identity->private_key)) != 0) {
        printf("Invalid private key in identity file\n");
        return -1;
    }

    return 0;
}

static int get_local_ip_for_client(
    struct sockaddr_in *client_addr,
    char *ip_buffer,
    size_t ip_buffer_size
) {
    int temp_sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (temp_sock < 0) {
        return -1;
    }

    if (connect(temp_sock, (struct sockaddr *)client_addr, sizeof(*client_addr)) < 0) {
        close(temp_sock);
        return -1;
    }

    struct sockaddr_in local_addr;
    socklen_t local_len = sizeof(local_addr);

    if (getsockname(temp_sock, (struct sockaddr *)&local_addr, &local_len) < 0) {
        close(temp_sock);
        return -1;
    }

    const char *result = inet_ntop(
        AF_INET,
        &local_addr.sin_addr,
        ip_buffer,
        ip_buffer_size
    );

    close(temp_sock);

    return result == NULL ? -1 : 0;
}

static int same_client(
    const SecureSession *session,
    const struct sockaddr_in *client_addr
) {
    return session->active &&
           session->client_addr.sin_addr.s_addr == client_addr->sin_addr.s_addr;
}

static void handle_discovery_request(
    int discovery_sock,
    const RobotIdentity *identity
) {
    DiscoveryRequestPacket request;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    ssize_t received = recvfrom(
        discovery_sock,
        &request,
        sizeof(request),
        0,
        (struct sockaddr *)&client_addr,
        &client_len
    );

    if (received != sizeof(DiscoveryRequestPacket)) {
        printf("Invalid discovery request size\n");
        return;
    }

    if (strncmp(request.magic, DISCOVERY_REQUEST_MAGIC, MAGIC_SIZE) != 0) {
        printf("Invalid discovery request magic\n");
        return;
    }

    if (!is_timestamp_fresh(request.timestamp)) {
        printf("Old discovery request ignored\n");
        return;
    }

    char local_ip[IP_SIZE] = {0};

    if (get_local_ip_for_client(&client_addr, local_ip, sizeof(local_ip)) != 0) {
        strncpy(local_ip, "0.0.0.0", IP_SIZE - 1);
    }

    DiscoveryResponsePacket response;
    memset(&response, 0, sizeof(response));

    strncpy(response.body.magic, DISCOVERY_RESPONSE_MAGIC, MAGIC_SIZE);
    strncpy(response.body.device_id, identity->device_id, DEVICE_ID_SIZE - 1);
    strncpy(response.body.serial_number, identity->serial_number, SERIAL_SIZE - 1);
    strncpy(response.body.ip_address, local_ip, IP_SIZE - 1);

    response.body.service_port = DATA_PORT;
    memcpy(response.body.public_key, identity->public_key, crypto_sign_PUBLICKEYBYTES);
    response.body.challenge_nonce = request.challenge_nonce;
    response.body.timestamp = (uint64_t)time(NULL);

    crypto_sign_detached(
        response.signature,
        NULL,
        (unsigned char *)&response.body,
        sizeof(DiscoveryResponseBody),
        identity->private_key
    );

    sendto(
        discovery_sock,
        &response,
        sizeof(response),
        0,
        (struct sockaddr *)&client_addr,
        client_len
    );

    printf(
        "Discovery response sent | device=%s ip=%s port=%d\n",
        identity->device_id,
        local_ip,
        DATA_PORT
    );
}

static void handle_key_exchange_request(
    int data_sock,
    const RobotIdentity *identity,
    SecureSession *session,
    const KeyExchangeRequestPacket *request,
    const struct sockaddr_in *client_addr,
    socklen_t client_len
) {
    if (strncmp(request->device_id, identity->device_id, DEVICE_ID_SIZE) != 0 ||
        strncmp(request->serial_number, identity->serial_number, SERIAL_SIZE) != 0) {
        printf("Key exchange identity mismatch ignored\n");
        return;
    }

    if (!is_timestamp_fresh(request->timestamp)) {
        printf("Old key exchange request ignored\n");
        return;
    }

    SecureSession new_session;
    memset(&new_session, 0, sizeof(new_session));

    crypto_kx_keypair(
        new_session.server_kx_public_key,
        new_session.server_kx_private_key
    );

    memcpy(
        new_session.client_kx_public_key,
        request->client_kx_public_key,
        crypto_kx_PUBLICKEYBYTES
    );

    if (crypto_kx_server_session_keys(
            new_session.rx_key,
            new_session.tx_key,
            new_session.server_kx_public_key,
            new_session.server_kx_private_key,
            new_session.client_kx_public_key
        ) != 0) {
        printf("Failed to derive server session keys\n");
        sodium_memzero(&new_session, sizeof(new_session));
        return;
    }

    KeyExchangeResponsePacket response;
    memset(&response, 0, sizeof(response));

    strncpy(response.body.magic, KX_RESPONSE_MAGIC, MAGIC_SIZE);
    strncpy(response.body.device_id, identity->device_id, DEVICE_ID_SIZE - 1);
    strncpy(response.body.serial_number, identity->serial_number, SERIAL_SIZE - 1);
    memcpy(
        response.body.client_kx_public_key,
        request->client_kx_public_key,
        crypto_kx_PUBLICKEYBYTES
    );
    memcpy(
        response.body.server_kx_public_key,
        new_session.server_kx_public_key,
        crypto_kx_PUBLICKEYBYTES
    );
    response.body.challenge_nonce = request->challenge_nonce;
    response.body.timestamp = (uint64_t)time(NULL);

    crypto_sign_detached(
        response.signature,
        NULL,
        (unsigned char *)&response.body,
        sizeof(KeyExchangeResponseBody),
        identity->private_key
    );

    if (sendto(
            data_sock,
            &response,
            sizeof(response),
            0,
            (const struct sockaddr *)client_addr,
            client_len
        ) < 0) {
        perror("key exchange response send failed");
        sodium_memzero(&new_session, sizeof(new_session));
        return;
    }

    new_session.active = 1;
    new_session.client_addr = *client_addr;
    new_session.last_request_sequence = 0;
    new_session.next_response_sequence = 1;

    sodium_memzero(session, sizeof(*session));
    *session = new_session;
    sodium_memzero(&new_session, sizeof(new_session));

    printf("Secure session established for client %s\n", inet_ntoa(client_addr->sin_addr));
}

static void send_file_failed(
    int data_sock,
    const struct sockaddr_in *client_addr,
    socklen_t client_len,
    const SecureSession *session,
    uint64_t transfer_id,
    uint32_t sequence_number,
    const char *message
) {
    FileTransferFailedPlain failed;
    memset(&failed, 0, sizeof(failed));

    copy_text(failed.magic, MAGIC_SIZE, FILE_PACKET_MAGIC);
    failed.packet_type = PACKET_TYPE_FILE_TRANSFER_FAILED;
    failed.transfer_id = transfer_id;
    failed.sequence_number = sequence_number;
    failed.timestamp = (uint64_t)time(NULL);
    failed.error_code = -1;
    copy_text(failed.message, sizeof(failed.message), message);

    send_encrypted_packet(
        data_sock,
        client_addr,
        client_len,
        session,
        &failed,
        sizeof(failed)
    );
}

static void send_meta_ack(
    int data_sock,
    const struct sockaddr_in *client_addr,
    socklen_t client_len,
    const SecureSession *session,
    uint64_t transfer_id,
    uint32_t sequence_number,
    int accepted,
    const char *message
) {
    FileMetaAckPlain ack;
    memset(&ack, 0, sizeof(ack));

    copy_text(ack.magic, MAGIC_SIZE, FILE_PACKET_MAGIC);
    ack.packet_type = PACKET_TYPE_FILE_META_ACK;
    ack.transfer_id = transfer_id;
    ack.sequence_number = sequence_number;
    ack.timestamp = (uint64_t)time(NULL);
    ack.accepted = accepted;
    copy_text(ack.message, sizeof(ack.message), message);

    send_encrypted_packet(data_sock, client_addr, client_len, session, &ack, sizeof(ack));
}

static void send_chunk_ack(
    int data_sock,
    const struct sockaddr_in *client_addr,
    socklen_t client_len,
    const SecureSession *session,
    uint64_t transfer_id,
    uint32_t sequence_number,
    uint32_t chunk_index,
    int status,
    const char *message
) {
    FileChunkAckPlain ack;
    memset(&ack, 0, sizeof(ack));

    copy_text(ack.magic, MAGIC_SIZE, FILE_PACKET_MAGIC);
    ack.packet_type = PACKET_TYPE_FILE_CHUNK_ACK;
    ack.transfer_id = transfer_id;
    ack.sequence_number = sequence_number;
    ack.timestamp = (uint64_t)time(NULL);
    ack.chunk_index = chunk_index;
    ack.status = status;
    copy_text(ack.message, sizeof(ack.message), message);

    send_encrypted_packet(data_sock, client_addr, client_len, session, &ack, sizeof(ack));
}

static int handle_file_metadata(
    int data_sock,
    const struct sockaddr_in *client_addr,
    socklen_t client_len,
    const SecureSession *session,
    FileTransferState *transfer,
    const FileMetaPlain *meta
) {
    if (strncmp(meta->magic, FILE_PACKET_MAGIC, MAGIC_SIZE) != 0 ||
        meta->packet_type != PACKET_TYPE_FILE_META ||
        !is_timestamp_fresh(meta->timestamp)) {
        return -1;
    }

    if (!sanitize_filename(meta->file_name) ||
        meta->file_size == 0 ||
        meta->file_size > MAX_FILE_SIZE ||
        meta->chunk_size == 0 ||
        meta->chunk_size > CHUNK_SIZE ||
        meta->total_chunks == 0 ||
        meta->total_chunks !=
            (uint32_t)((meta->file_size + meta->chunk_size - 1) / meta->chunk_size)) {
        send_meta_ack(
            data_sock,
            client_addr,
            client_len,
            session,
            meta->transfer_id,
            meta->sequence_number,
            0,
            "Invalid file metadata"
        );
        return -1;
    }

    if (transfer->active && transfer->transfer_id == meta->transfer_id) {
        if (strncmp(transfer->file_name, meta->file_name, FILE_NAME_SIZE) == 0 &&
            transfer->file_size == meta->file_size &&
            transfer->chunk_size == meta->chunk_size &&
            transfer->total_chunks == meta->total_chunks &&
            sodium_memcmp(
                transfer->expected_sha256,
                meta->file_sha256,
                crypto_hash_sha256_BYTES
            ) == 0) {
            send_meta_ack(
                data_sock,
                client_addr,
                client_len,
                session,
                meta->transfer_id,
                meta->sequence_number,
                1,
                "Accepted"
            );
            return 0;
        }

        send_meta_ack(
            data_sock,
            client_addr,
            client_len,
            session,
            meta->transfer_id,
            meta->sequence_number,
            0,
            "Conflicting duplicate metadata"
        );
        return -1;
    }

    if (create_downloads_directory() != 0) {
        send_meta_ack(
            data_sock,
            client_addr,
            client_len,
            session,
            meta->transfer_id,
            meta->sequence_number,
            0,
            "Cannot create downloads directory"
        );
        return -1;
    }

    FileTransferState new_transfer;
    memset(&new_transfer, 0, sizeof(new_transfer));

    new_transfer.received_bitmap = (unsigned char *)calloc(meta->total_chunks, 1);

    if (new_transfer.received_bitmap == NULL) {
        send_meta_ack(
            data_sock,
            client_addr,
            client_len,
            session,
            meta->transfer_id,
            meta->sequence_number,
            0,
            "Out of memory"
        );
        return -1;
    }

    copy_text(new_transfer.file_name, sizeof(new_transfer.file_name), meta->file_name);
    snprintf(
        new_transfer.part_path,
        sizeof(new_transfer.part_path),
        "%s/%llu_%s.part",
        DOWNLOAD_DIR,
        (unsigned long long)meta->transfer_id,
        new_transfer.file_name
    );
    snprintf(
        new_transfer.final_path,
        sizeof(new_transfer.final_path),
        "%s/%s",
        DOWNLOAD_DIR,
        new_transfer.file_name
    );

    if (access(new_transfer.final_path, F_OK) == 0) {
        free(new_transfer.received_bitmap);
        send_meta_ack(
            data_sock,
            client_addr,
            client_len,
            session,
            meta->transfer_id,
            meta->sequence_number,
            0,
            "Final file already exists"
        );
        return -1;
    }

    new_transfer.file = fopen(new_transfer.part_path, "w+b");

    if (new_transfer.file == NULL) {
        free(new_transfer.received_bitmap);
        send_meta_ack(
            data_sock,
            client_addr,
            client_len,
            session,
            meta->transfer_id,
            meta->sequence_number,
            0,
            "Cannot create output file"
        );
        return -1;
    }

    cleanup_file_transfer(transfer);

    new_transfer.active = 1;
    new_transfer.transfer_id = meta->transfer_id;
    new_transfer.file_size = meta->file_size;
    new_transfer.chunk_size = meta->chunk_size;
    new_transfer.total_chunks = meta->total_chunks;
    memcpy(
        new_transfer.expected_sha256,
        meta->file_sha256,
        crypto_hash_sha256_BYTES
    );

    *transfer = new_transfer;

    send_meta_ack(
        data_sock,
        client_addr,
        client_len,
        session,
        transfer->transfer_id,
        meta->sequence_number,
        1,
        "Accepted"
    );

    printf(
        "File transfer accepted | name=%s size=%llu chunks=%u\n",
        transfer->file_name,
        (unsigned long long)transfer->file_size,
        transfer->total_chunks
    );

    return 0;
}

static void handle_file_chunk(
    int data_sock,
    const struct sockaddr_in *client_addr,
    socklen_t client_len,
    const SecureSession *session,
    FileTransferState *transfer,
    const FileChunkPlain *chunk
) {
    uint64_t expected_offset;
    uint32_t expected_size;

    if (!transfer->active ||
        chunk->transfer_id != transfer->transfer_id ||
        !is_timestamp_fresh(chunk->timestamp) ||
        chunk->chunk_index >= transfer->total_chunks ||
        chunk->chunk_size == 0 ||
        chunk->chunk_size > transfer->chunk_size ||
        chunk->chunk_size > CHUNK_SIZE) {
        send_chunk_ack(
            data_sock,
            client_addr,
            client_len,
            session,
            chunk->transfer_id,
            chunk->sequence_number,
            chunk->chunk_index,
            0,
            "Invalid chunk"
        );
        return;
    }

    expected_offset = (uint64_t)chunk->chunk_index * transfer->chunk_size;
    expected_size = transfer->chunk_size;

    if (chunk->chunk_index + 1 == transfer->total_chunks) {
        expected_size = (uint32_t)(transfer->file_size - expected_offset);
    }

    if (chunk->offset != expected_offset || chunk->chunk_size != expected_size) {
        send_chunk_ack(
            data_sock,
            client_addr,
            client_len,
            session,
            chunk->transfer_id,
            chunk->sequence_number,
            chunk->chunk_index,
            0,
            "Chunk offset/size mismatch"
        );
        return;
    }

    if (transfer->received_bitmap[chunk->chunk_index]) {
        send_chunk_ack(
            data_sock,
            client_addr,
            client_len,
            session,
            transfer->transfer_id,
            chunk->sequence_number,
            chunk->chunk_index,
            1,
            "Duplicate ACK"
        );
        return;
    }

    if (fseek(transfer->file, (long)chunk->offset, SEEK_SET) != 0 ||
        fwrite(chunk->data, 1, chunk->chunk_size, transfer->file) != chunk->chunk_size) {
        send_chunk_ack(
            data_sock,
            client_addr,
            client_len,
            session,
            transfer->transfer_id,
            chunk->sequence_number,
            chunk->chunk_index,
            0,
            "File write failed"
        );
        return;
    }

    transfer->received_bitmap[chunk->chunk_index] = 1;
    transfer->received_chunks++;

    send_chunk_ack(
        data_sock,
        client_addr,
        client_len,
        session,
        transfer->transfer_id,
        chunk->sequence_number,
        chunk->chunk_index,
        1,
        "OK"
    );
}

static void handle_file_status_request(
    int data_sock,
    const struct sockaddr_in *client_addr,
    socklen_t client_len,
    const SecureSession *session,
    const FileTransferState *transfer,
    const FileStatusRequestPlain *request
) {
    FileStatusResponsePlain response;
    memset(&response, 0, sizeof(response));

    copy_text(response.magic, MAGIC_SIZE, FILE_PACKET_MAGIC);
    response.packet_type = PACKET_TYPE_FILE_STATUS_RESPONSE;
    response.transfer_id = request->transfer_id;
    response.sequence_number = request->sequence_number;
    response.timestamp = (uint64_t)time(NULL);

    if (transfer->active && request->transfer_id == transfer->transfer_id) {
        response.total_chunks = transfer->total_chunks;
        response.received_chunks = transfer->received_chunks;

        for (uint32_t i = 0;
             i < transfer->total_chunks && response.missing_count < MAX_MISSING_LIST;
             i++) {
            if (!transfer->received_bitmap[i]) {
                response.missing_indices[response.missing_count++] = i;
            }
        }
    }

    send_encrypted_packet(
        data_sock,
        client_addr,
        client_len,
        session,
        &response,
        sizeof(response)
    );
}

static void handle_file_complete(
    int data_sock,
    const struct sockaddr_in *client_addr,
    socklen_t client_len,
    const SecureSession *session,
    FileTransferState *transfer,
    const FileCompleteRequestPlain *request
) {
    FileCompleteResponsePlain response;
    unsigned char computed_hash[crypto_hash_sha256_BYTES];
    int success = 0;

    memset(&response, 0, sizeof(response));
    copy_text(response.magic, MAGIC_SIZE, FILE_PACKET_MAGIC);
    response.packet_type = PACKET_TYPE_FILE_COMPLETE_RESPONSE;
    response.transfer_id = request->transfer_id;
    response.sequence_number = request->sequence_number;
    response.timestamp = (uint64_t)time(NULL);

    if (!transfer->active || request->transfer_id != transfer->transfer_id) {
        copy_text(response.message, sizeof(response.message), "No active transfer");
    } else if (transfer->received_chunks != transfer->total_chunks) {
        copy_text(response.message, sizeof(response.message), "Missing chunks");
    } else {
        fflush(transfer->file);
        fclose(transfer->file);
        transfer->file = NULL;

        if (compute_file_sha256(transfer->part_path, computed_hash) != 0) {
            copy_text(response.message, sizeof(response.message), "Hash computation failed");
        } else {
            memcpy(response.computed_sha256, computed_hash, crypto_hash_sha256_BYTES);

            if (sodium_memcmp(
                    computed_hash,
                    transfer->expected_sha256,
                    crypto_hash_sha256_BYTES
                ) != 0) {
                copy_text(response.message, sizeof(response.message), "SHA-256 mismatch");
            } else if (access(transfer->final_path, F_OK) == 0) {
                copy_text(response.message, sizeof(response.message), "Final file already exists");
            } else if (rename(transfer->part_path, transfer->final_path) != 0) {
                copy_text(response.message, sizeof(response.message), "Rename failed");
            } else {
                success = 1;
                transfer->complete = 1;
                copy_text(response.final_file_path, sizeof(response.final_file_path), transfer->final_path);
                copy_text(response.message, sizeof(response.message), "File transfer complete");
            }
        }
    }

    response.success = success;

    send_encrypted_packet(
        data_sock,
        client_addr,
        client_len,
        session,
        &response,
        sizeof(response)
    );

    if (success) {
        printf("File transfer complete | saved=%s\n", transfer->final_path);
        cleanup_file_transfer(transfer);
    }
}

static void handle_file_packet(
    int data_sock,
    const struct sockaddr_in *client_addr,
    socklen_t client_len,
    const SecureSession *session,
    FileTransferState *transfer,
    const EncryptedFilePacket *packet,
    size_t packet_len
) {
    unsigned char plain[MAX_FILE_PLAINTEXT_SIZE];
    size_t plain_len = 0;
    uint32_t packet_type;

    if (!same_client(session, client_addr)) {
        printf("Encrypted file packet without active session ignored\n");
        return;
    }

    if (decrypt_packet(
            session,
            packet,
            packet_len,
            plain,
            sizeof(plain),
            &plain_len
        ) != 0) {
        printf("Encrypted file packet authentication failed\n");
        return;
    }

    if (plain_len < MAGIC_SIZE + sizeof(uint32_t)) {
        printf("Invalid encrypted file plaintext size\n");
        return;
    }

    if (strncmp((char *)plain, FILE_PACKET_MAGIC, MAGIC_SIZE) != 0) {
        printf("Invalid encrypted file plaintext magic\n");
        return;
    }

    memcpy(&packet_type, plain + MAGIC_SIZE, sizeof(packet_type));

    switch (packet_type) {
        case PACKET_TYPE_FILE_META:
            if (plain_len == sizeof(FileMetaPlain)) {
                handle_file_metadata(
                    data_sock,
                    client_addr,
                    client_len,
                    session,
                    transfer,
                    (const FileMetaPlain *)plain
                );
            }
            break;

        case PACKET_TYPE_FILE_CHUNK:
            if (plain_len == sizeof(FileChunkPlain)) {
                handle_file_chunk(
                    data_sock,
                    client_addr,
                    client_len,
                    session,
                    transfer,
                    (const FileChunkPlain *)plain
                );
            }
            break;

        case PACKET_TYPE_FILE_STATUS_REQUEST:
            if (plain_len == sizeof(FileStatusRequestPlain)) {
                handle_file_status_request(
                    data_sock,
                    client_addr,
                    client_len,
                    session,
                    transfer,
                    (const FileStatusRequestPlain *)plain
                );
            }
            break;

        case PACKET_TYPE_FILE_COMPLETE_REQUEST:
            if (plain_len == sizeof(FileCompleteRequestPlain)) {
                handle_file_complete(
                    data_sock,
                    client_addr,
                    client_len,
                    session,
                    transfer,
                    (const FileCompleteRequestPlain *)plain
                );
            }
            break;

        default:
            send_file_failed(
                data_sock,
                client_addr,
                client_len,
                session,
                0,
                0,
                "Unknown file packet type"
            );
            break;
    }
}

static void handle_encrypted_data_request(
    int data_sock,
    const RobotIdentity *identity,
    const RobotSharedData *shared_data,
    SecureSession *session,
    const EncryptedDataRequestPacket *encrypted_request,
    const struct sockaddr_in *client_addr,
    socklen_t client_len
) {
    if (!same_client(session, client_addr)) {
        printf("Encrypted request without active session ignored\n");
        return;
    }

    EncryptedDataRequestBody request_body;
    unsigned long long decrypted_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            (unsigned char *)&request_body,
            &decrypted_len,
            NULL,
            encrypted_request->ciphertext,
            sizeof(encrypted_request->ciphertext),
            NULL,
            0,
            encrypted_request->nonce,
            session->rx_key
        ) != 0) {
        printf("Encrypted request authentication failed\n");
        return;
    }

    if (decrypted_len != sizeof(EncryptedDataRequestBody)) {
        printf("Invalid encrypted request plaintext size\n");
        return;
    }

    if (strncmp(request_body.magic, DATA_REQUEST_MAGIC, MAGIC_SIZE) != 0) {
        printf("Invalid encrypted request magic\n");
        return;
    }

    if (strncmp(request_body.device_id, identity->device_id, DEVICE_ID_SIZE) != 0 ||
        strncmp(request_body.serial_number, identity->serial_number, SERIAL_SIZE) != 0) {
        printf("Encrypted request identity mismatch ignored\n");
        return;
    }

    if (!is_timestamp_fresh(request_body.timestamp)) {
        printf("Old encrypted request ignored\n");
        return;
    }

    if (request_body.request_sequence <= session->last_request_sequence) {
        printf("Replayed encrypted request ignored\n");
        return;
    }

    session->last_request_sequence = request_body.request_sequence;

    EncryptedDataResponseBody response_body;
    memset(&response_body, 0, sizeof(response_body));

    strncpy(response_body.magic, DATA_RESPONSE_MAGIC, MAGIC_SIZE);
    strncpy(response_body.device_id, identity->device_id, DEVICE_ID_SIZE - 1);
    strncpy(response_body.serial_number, identity->serial_number, SERIAL_SIZE - 1);
    response_body.response_sequence = session->next_response_sequence++;
    response_body.challenge_nonce = request_body.challenge_nonce;
    response_body.timestamp = (uint64_t)time(NULL);
    response_body.counter = shared_data->counter;
    response_body.battery_level = shared_data->battery_level;
    response_body.temperature = shared_data->temperature;
    strncpy(response_body.message, shared_data->message, MESSAGE_SIZE - 1);

    EncryptedDataResponsePacket encrypted_response;
    unsigned long long encrypted_len = 0;
    memset(&encrypted_response, 0, sizeof(encrypted_response));

    strncpy(encrypted_response.magic, ENCRYPTED_DATA_RESPONSE_MAGIC, MAGIC_SIZE);
    randombytes_buf(
        encrypted_response.nonce,
        sizeof(encrypted_response.nonce)
    );

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            encrypted_response.ciphertext,
            &encrypted_len,
            (unsigned char *)&response_body,
            sizeof(response_body),
            NULL,
            0,
            NULL,
            encrypted_response.nonce,
            session->tx_key
        ) != 0) {
        printf("Encrypted response creation failed\n");
        return;
    }

    if (encrypted_len != sizeof(encrypted_response.ciphertext)) {
        printf("Unexpected encrypted response length\n");
        return;
    }

    sendto(
        data_sock,
        &encrypted_response,
        sizeof(encrypted_response),
        0,
        (const struct sockaddr *)client_addr,
        client_len
    );

    printf(
        "Encrypted data sent | seq=%u counter=%d battery=%.2f temp=%.2f\n",
        response_body.response_sequence,
        response_body.counter,
        response_body.battery_level,
        response_body.temperature
    );
}

static void handle_data_socket(
    int data_sock,
    const RobotIdentity *identity,
    const RobotSharedData *shared_data,
    SecureSession *session,
    FileTransferState *transfer
) {
    unsigned char buffer[2048];
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    ssize_t received = recvfrom(
        data_sock,
        buffer,
        sizeof(buffer),
        0,
        (struct sockaddr *)&client_addr,
        &client_len
    );

    if (received < (ssize_t)MAGIC_SIZE) {
        printf("Invalid data socket packet size\n");
        return;
    }

    if (strncmp((char *)buffer, KX_REQUEST_MAGIC, MAGIC_SIZE) == 0) {
        if (received != sizeof(KeyExchangeRequestPacket)) {
            printf("Invalid key exchange request size\n");
            return;
        }

        handle_key_exchange_request(
            data_sock,
            identity,
            session,
            (KeyExchangeRequestPacket *)buffer,
            &client_addr,
            client_len
        );
        cleanup_file_transfer(transfer);
        return;
    }

    if (strncmp((char *)buffer, ENCRYPTED_DATA_REQUEST_MAGIC, MAGIC_SIZE) == 0) {
        if (received != sizeof(EncryptedDataRequestPacket)) {
            printf("Invalid encrypted request size\n");
            return;
        }

        handle_encrypted_data_request(
            data_sock,
            identity,
            shared_data,
            session,
            (EncryptedDataRequestPacket *)buffer,
            &client_addr,
            client_len
        );
        return;
    }

    if (strncmp((char *)buffer, FILE_PACKET_MAGIC, MAGIC_SIZE) == 0) {
        handle_file_packet(
            data_sock,
            &client_addr,
            client_len,
            session,
            transfer,
            (EncryptedFilePacket *)buffer,
            (size_t)received
        );
        return;
    }

    printf("Unknown data socket packet magic ignored\n");
}

int main() {
    if (sodium_init() < 0) {
        printf("libsodium initialization failed\n");
        return 1;
    }

    RobotIdentity identity;

    if (load_identity(&identity) != 0) {
        return 1;
    }

    int shm_fd = shm_open(SHM_NAME, O_RDWR, 0666);

    if (shm_fd == -1) {
        perror("shm_open failed. Run shm_writer first");
        return 1;
    }

    RobotSharedData *shared_data = mmap(
        NULL,
        SHM_SIZE,
        PROT_READ,
        MAP_SHARED,
        shm_fd,
        0
    );

    if (shared_data == MAP_FAILED) {
        perror("mmap failed");
        close(shm_fd);
        return 1;
    }

    int discovery_sock = socket(AF_INET, SOCK_DGRAM, 0);
    int data_sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (discovery_sock < 0 || data_sock < 0) {
        perror("socket failed");
        munmap(shared_data, SHM_SIZE);
        close(shm_fd);
        return 1;
    }

    int reuse = 1;
    int udp_buffer_size = UDP_BUFFER_SIZE;

    setsockopt(discovery_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(data_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(data_sock, SOL_SOCKET, SO_RCVBUF, &udp_buffer_size, sizeof(udp_buffer_size));
    setsockopt(data_sock, SOL_SOCKET, SO_SNDBUF, &udp_buffer_size, sizeof(udp_buffer_size));

    struct sockaddr_in discovery_addr;
    memset(&discovery_addr, 0, sizeof(discovery_addr));

    discovery_addr.sin_family = AF_INET;
    discovery_addr.sin_addr.s_addr = INADDR_ANY;
    discovery_addr.sin_port = htons(DISCOVERY_PORT);

    if (bind(discovery_sock, (struct sockaddr *)&discovery_addr, sizeof(discovery_addr)) < 0) {
        perror("discovery bind failed");
        close(discovery_sock);
        close(data_sock);
        munmap(shared_data, SHM_SIZE);
        close(shm_fd);
        return 1;
    }

    struct sockaddr_in data_addr;
    memset(&data_addr, 0, sizeof(data_addr));

    data_addr.sin_family = AF_INET;
    data_addr.sin_addr.s_addr = INADDR_ANY;
    data_addr.sin_port = htons(DATA_PORT);

    if (bind(data_sock, (struct sockaddr *)&data_addr, sizeof(data_addr)) < 0) {
        perror("data bind failed");
        close(discovery_sock);
        close(data_sock);
        munmap(shared_data, SHM_SIZE);
        close(shm_fd);
        return 1;
    }

    printf("Robot secure UDP service started\n");
    printf("Device ID      : %s\n", identity.device_id);
    printf("Serial Number  : %s\n", identity.serial_number);
    printf("Discovery port : %d\n", DISCOVERY_PORT);
    printf("Data/KX port   : %d\n", DATA_PORT);

    SecureSession session;
    memset(&session, 0, sizeof(session));

    FileTransferState transfer;
    memset(&transfer, 0, sizeof(transfer));

    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(discovery_sock, &read_fds);
        FD_SET(data_sock, &read_fds);

        int max_fd = discovery_sock > data_sock ? discovery_sock : data_sock;

        int ready = select(max_fd + 1, &read_fds, NULL, NULL, NULL);

        if (ready < 0) {
            perror("select failed");
            continue;
        }

        if (FD_ISSET(discovery_sock, &read_fds)) {
            handle_discovery_request(discovery_sock, &identity);
        }

        if (FD_ISSET(data_sock, &read_fds)) {
            handle_data_socket(data_sock, &identity, shared_data, &session, &transfer);
        }
    }

    cleanup_file_transfer(&transfer);
    sodium_memzero(&session, sizeof(session));
    close(discovery_sock);
    close(data_sock);
    munmap(shared_data, SHM_SIZE);
    close(shm_fd);

    return 0;
}
