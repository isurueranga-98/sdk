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
#include <sys/mman.h>
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

#define DISCOVERY_REQUEST_MAGIC "RDISCOV"
#define DISCOVERY_RESPONSE_MAGIC "RRESPON"
#define KX_REQUEST_MAGIC "RKXREQ"
#define KX_RESPONSE_MAGIC "RKXRES"
#define ENCRYPTED_DATA_REQUEST_MAGIC "RENCQ"
#define ENCRYPTED_DATA_RESPONSE_MAGIC "RENCR"
#define DATA_REQUEST_MAGIC "EDATAQ"
#define DATA_RESPONSE_MAGIC "EDATAR"

#define FRESHNESS_WINDOW_SECONDS 10

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
    SecureSession *session
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
    setsockopt(discovery_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(data_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

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
            handle_data_socket(data_sock, &identity, shared_data, &session);
        }
    }

    sodium_memzero(&session, sizeof(session));
    close(discovery_sock);
    close(data_sock);
    munmap(shared_data, SHM_SIZE);
    close(shm_fd);

    return 0;
}
