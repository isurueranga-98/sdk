// windows_client/windows_robot_client.c
//
// Secure Windows robot client:
//   1. Plain UDP broadcast discovery.
//   2. TOFU pairing using the robot Ed25519 signing public key.
//   3. Signed crypto_kx key exchange.
//   4. Encrypted/authenticated robot data polling with XChaCha20-Poly1305.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <sodium.h>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#endif

#define TRUSTED_FILE "trusted_robots.txt"

#define DISCOVERY_PORT 5005

#define MAGIC_SIZE 8
#define DEVICE_ID_SIZE 32
#define SERIAL_SIZE 32
#define IP_SIZE 32
#define MESSAGE_SIZE 256

#define MAX_ROBOTS 20
#define MAX_TRUSTED_ROBOTS 50
#define DISCOVERY_SEND_ROUNDS 3
#define DISCOVERY_ROUND_DELAY_MS 250

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
} TrustedRobot;

typedef struct {
    char device_id[DEVICE_ID_SIZE];
    char serial_number[SERIAL_SIZE];
    char ip_address[IP_SIZE];
    uint16_t service_port;
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    int trusted;
} DiscoveredRobot;

typedef struct {
    unsigned char client_kx_public_key[crypto_kx_PUBLICKEYBYTES];
    unsigned char client_kx_private_key[crypto_kx_SECRETKEYBYTES];
    unsigned char server_kx_public_key[crypto_kx_PUBLICKEYBYTES];
    unsigned char rx_key[crypto_kx_SESSIONKEYBYTES];
    unsigned char tx_key[crypto_kx_SESSIONKEYBYTES];
    uint32_t next_request_sequence;
    uint32_t last_response_sequence;
} SecureSession;

static void public_key_to_hex(
    const unsigned char *public_key,
    char *hex,
    size_t hex_size
) {
    sodium_bin2hex(
        hex,
        hex_size,
        public_key,
        crypto_sign_PUBLICKEYBYTES
    );
}

static int hex_to_bytes(
    const char *hex,
    unsigned char *output,
    size_t output_size
) {
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

static void copy_text_field(
    char *destination,
    size_t destination_size,
    const char *source,
    size_t source_size
) {
    size_t length = 0;

    if (destination_size == 0) {
        return;
    }

    while (length + 1 < destination_size &&
           length < source_size &&
           source[length] != '\0') {
        destination[length] = source[length];
        length++;
    }

    destination[length] = '\0';
}

static void copy_text(
    char *destination,
    size_t destination_size,
    const char *source
) {
    size_t length = 0;

    if (destination_size == 0) {
        return;
    }

    while (length + 1 < destination_size && source[length] != '\0') {
        destination[length] = source[length];
        length++;
    }

    destination[length] = '\0';
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

static int load_trusted_robots(
    TrustedRobot *trusted_robots,
    int max_count
) {
    FILE *file = fopen(TRUSTED_FILE, "r");

    if (file == NULL) {
        return 0;
    }

    int count = 0;
    char line[512];

    while (fgets(line, sizeof(line), file) && count < max_count) {
        remove_newline(line);

        char *device_id = strtok(line, "|");
        char *serial_number = strtok(NULL, "|");
        char *public_key_hex = strtok(NULL, "|");

        if (device_id == NULL || serial_number == NULL || public_key_hex == NULL) {
            continue;
        }

        memset(&trusted_robots[count], 0, sizeof(TrustedRobot));

        copy_text(trusted_robots[count].device_id, DEVICE_ID_SIZE, device_id);
        copy_text(trusted_robots[count].serial_number, SERIAL_SIZE, serial_number);

        if (hex_to_bytes(
                public_key_hex,
                trusted_robots[count].public_key,
                crypto_sign_PUBLICKEYBYTES
            ) != 0) {
            continue;
        }

        count++;
    }

    fclose(file);
    return count;
}

static int save_trusted_robot(const TrustedRobot *robot) {
    FILE *file = fopen(TRUSTED_FILE, "a");

    if (file == NULL) {
        perror("Failed to open trusted_robots.txt");
        return -1;
    }

    char public_key_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];

    public_key_to_hex(
        robot->public_key,
        public_key_hex,
        sizeof(public_key_hex)
    );

    fprintf(
        file,
        "%s|%s|%s\n",
        robot->device_id,
        robot->serial_number,
        public_key_hex
    );

    fclose(file);
    return 0;
}

static int find_trusted_robot(
    TrustedRobot *trusted_robots,
    int trusted_count,
    const char *device_id,
    const char *serial_number
) {
    for (int i = 0; i < trusted_count; i++) {
        if (strncmp(trusted_robots[i].device_id, device_id, DEVICE_ID_SIZE) == 0 &&
            strncmp(trusted_robots[i].serial_number, serial_number, SERIAL_SIZE) == 0) {
            return i;
        }
    }

    return -1;
}

static int is_same_public_key(
    const unsigned char *a,
    const unsigned char *b
) {
    return sodium_memcmp(a, b, crypto_sign_PUBLICKEYBYTES) == 0;
}

static int is_duplicate_robot(
    DiscoveredRobot *robots,
    int count,
    const char *device_id,
    const char *serial_number
) {
    for (int i = 0; i < count; i++) {
        if (strncmp(robots[i].device_id, device_id, DEVICE_ID_SIZE) == 0 &&
            strncmp(robots[i].serial_number, serial_number, SERIAL_SIZE) == 0) {
            return 1;
        }
    }

    return 0;
}

static int send_discovery_to_address(
    SOCKET discovery_sock,
    const DiscoveryRequestPacket *request,
    uint32_t address
) {
    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));

    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(DISCOVERY_PORT);
    broadcast_addr.sin_addr.s_addr = address;

    int sent = sendto(
        discovery_sock,
        (const char *)request,
        sizeof(*request),
        0,
        (struct sockaddr *)&broadcast_addr,
        sizeof(broadcast_addr)
    );

    if (sent == SOCKET_ERROR) {
        return -1;
    }

    return 0;
}

static int send_adapter_discovery_requests(
    SOCKET discovery_sock,
    const DiscoveryRequestPacket *request
) {
    ULONG buffer_size = 15 * 1024;
    IP_ADAPTER_ADDRESSES *adapters = NULL;
    DWORD flags = GAA_FLAG_SKIP_ANYCAST |
                  GAA_FLAG_SKIP_MULTICAST |
                  GAA_FLAG_SKIP_DNS_SERVER;
    DWORD result;
    int sent_count = 0;

    adapters = (IP_ADAPTER_ADDRESSES *)malloc(buffer_size);

    if (adapters == NULL) {
        return 0;
    }

    result = GetAdaptersAddresses(
        AF_INET,
        flags,
        NULL,
        adapters,
        &buffer_size
    );

    if (result == ERROR_BUFFER_OVERFLOW) {
        IP_ADAPTER_ADDRESSES *resized =
            (IP_ADAPTER_ADDRESSES *)realloc(adapters, buffer_size);

        if (resized == NULL) {
            free(adapters);
            return 0;
        }

        adapters = resized;
        result = GetAdaptersAddresses(
            AF_INET,
            flags,
            NULL,
            adapters,
            &buffer_size
        );
    }

    if (result != NO_ERROR) {
        free(adapters);
        return 0;
    }

    for (IP_ADAPTER_ADDRESSES *adapter = adapters;
         adapter != NULL;
         adapter = adapter->Next) {
        if (adapter->OperStatus != IfOperStatusUp ||
            adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK ||
            adapter->IfType == IF_TYPE_TUNNEL) {
            continue;
        }

        for (IP_ADAPTER_UNICAST_ADDRESS *unicast = adapter->FirstUnicastAddress;
             unicast != NULL;
             unicast = unicast->Next) {
            struct sockaddr_in *addr =
                (struct sockaddr_in *)unicast->Address.lpSockaddr;

            if (addr == NULL || addr->sin_family != AF_INET) {
                continue;
            }

            ULONG prefix = unicast->OnLinkPrefixLength;

            if (prefix > 30) {
                continue;
            }

            uint32_t ip_host = ntohl(addr->sin_addr.s_addr);
            uint32_t mask = prefix == 0 ? 0 : (0xffffffffUL << (32 - prefix));
            uint32_t broadcast_host = ip_host | ~mask;
            uint32_t broadcast_address = htonl(broadcast_host);

            if (send_discovery_to_address(
                    discovery_sock,
                    request,
                    broadcast_address
                ) == 0) {
                sent_count++;
            }
        }
    }

    free(adapters);
    return sent_count;
}

static int send_discovery_requests(
    SOCKET discovery_sock,
    const DiscoveryRequestPacket *request
) {
    int sent_count = 0;

    for (int round = 0; round < DISCOVERY_SEND_ROUNDS; round++) {
        if (send_discovery_to_address(
                discovery_sock,
                request,
                INADDR_BROADCAST
            ) == 0) {
            sent_count++;
        }

        sent_count += send_adapter_discovery_requests(discovery_sock, request);

        if (round + 1 < DISCOVERY_SEND_ROUNDS) {
            Sleep(DISCOVERY_ROUND_DELAY_MS);
        }
    }

    return sent_count;
}

static int perform_key_exchange(
    SOCKET data_sock,
    const struct sockaddr_in *robot_data_addr,
    const DiscoveredRobot *robot,
    SecureSession *session
) {
    memset(session, 0, sizeof(*session));

    crypto_kx_keypair(
        session->client_kx_public_key,
        session->client_kx_private_key
    );

    uint64_t kx_challenge;
    randombytes_buf(&kx_challenge, sizeof(kx_challenge));

    KeyExchangeRequestPacket request;
    memset(&request, 0, sizeof(request));

    copy_text(request.magic, MAGIC_SIZE, KX_REQUEST_MAGIC);
    copy_text(request.device_id, DEVICE_ID_SIZE, robot->device_id);
    copy_text(request.serial_number, SERIAL_SIZE, robot->serial_number);
    memcpy(
        request.client_kx_public_key,
        session->client_kx_public_key,
        crypto_kx_PUBLICKEYBYTES
    );
    request.challenge_nonce = kx_challenge;
    request.timestamp = (uint64_t)time(NULL);

    int sent = sendto(
        data_sock,
        (const char *)&request,
        sizeof(request),
        0,
        (const struct sockaddr *)robot_data_addr,
        sizeof(*robot_data_addr)
    );

    if (sent == SOCKET_ERROR) {
        printf("Key exchange request failed: %d\n", WSAGetLastError());
        return -1;
    }

    KeyExchangeResponsePacket response;
    struct sockaddr_in sender_addr;
    int sender_len = sizeof(sender_addr);

    int received = recvfrom(
        data_sock,
        (char *)&response,
        sizeof(response),
        0,
        (struct sockaddr *)&sender_addr,
        &sender_len
    );

    if (received == SOCKET_ERROR) {
        printf("No key exchange response received\n");
        return -1;
    }

    if (received != sizeof(KeyExchangeResponsePacket)) {
        printf("Invalid key exchange response size\n");
        return -1;
    }

    if (strncmp(response.body.magic, KX_RESPONSE_MAGIC, MAGIC_SIZE) != 0) {
        printf("Invalid key exchange response magic\n");
        return -1;
    }

    if (strncmp(response.body.device_id, robot->device_id, DEVICE_ID_SIZE) != 0 ||
        strncmp(response.body.serial_number, robot->serial_number, SERIAL_SIZE) != 0) {
        printf("Key exchange identity mismatch\n");
        return -1;
    }

    if (response.body.challenge_nonce != kx_challenge) {
        printf("Key exchange challenge mismatch\n");
        return -1;
    }

    if (!is_timestamp_fresh(response.body.timestamp)) {
        printf("Old key exchange response ignored\n");
        return -1;
    }

    if (sodium_memcmp(
            response.body.client_kx_public_key,
            session->client_kx_public_key,
            crypto_kx_PUBLICKEYBYTES
        ) != 0) {
        printf("Key exchange client public key echo mismatch\n");
        return -1;
    }

    int verify_result = crypto_sign_verify_detached(
        response.signature,
        (unsigned char *)&response.body,
        sizeof(KeyExchangeResponseBody),
        robot->public_key
    );

    if (verify_result != 0) {
        printf("Invalid signed key exchange response\n");
        return -1;
    }

    memcpy(
        session->server_kx_public_key,
        response.body.server_kx_public_key,
        crypto_kx_PUBLICKEYBYTES
    );

    if (crypto_kx_client_session_keys(
            session->rx_key,
            session->tx_key,
            session->client_kx_public_key,
            session->client_kx_private_key,
            session->server_kx_public_key
        ) != 0) {
        printf("Failed to derive client session keys\n");
        return -1;
    }

    session->next_request_sequence = 1;
    session->last_response_sequence = 0;

    printf("Secure encrypted session established.\n");
    return 0;
}

static int send_encrypted_data_request(
    SOCKET data_sock,
    const struct sockaddr_in *robot_data_addr,
    const DiscoveredRobot *robot,
    SecureSession *session,
    uint64_t *challenge_out
) {
    EncryptedDataRequestBody body;
    memset(&body, 0, sizeof(body));

    randombytes_buf(challenge_out, sizeof(*challenge_out));

    copy_text(body.magic, MAGIC_SIZE, DATA_REQUEST_MAGIC);
    copy_text(body.device_id, DEVICE_ID_SIZE, robot->device_id);
    copy_text(body.serial_number, SERIAL_SIZE, robot->serial_number);
    body.request_sequence = session->next_request_sequence++;
    body.challenge_nonce = *challenge_out;
    body.timestamp = (uint64_t)time(NULL);

    EncryptedDataRequestPacket packet;
    unsigned long long encrypted_len = 0;
    memset(&packet, 0, sizeof(packet));

    copy_text(packet.magic, MAGIC_SIZE, ENCRYPTED_DATA_REQUEST_MAGIC);
    randombytes_buf(packet.nonce, sizeof(packet.nonce));

    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            packet.ciphertext,
            &encrypted_len,
            (unsigned char *)&body,
            sizeof(body),
            NULL,
            0,
            NULL,
            packet.nonce,
            session->tx_key
        ) != 0) {
        printf("Failed to encrypt data request\n");
        return -1;
    }

    if (encrypted_len != sizeof(packet.ciphertext)) {
        printf("Unexpected encrypted request length\n");
        return -1;
    }

    int sent = sendto(
        data_sock,
        (const char *)&packet,
        sizeof(packet),
        0,
        (const struct sockaddr *)robot_data_addr,
        sizeof(*robot_data_addr)
    );

    if (sent == SOCKET_ERROR) {
        printf("Encrypted data request failed: %d\n", WSAGetLastError());
        return -1;
    }

    return 0;
}

static int receive_encrypted_data_response(
    SOCKET data_sock,
    const DiscoveredRobot *robot,
    SecureSession *session,
    uint64_t expected_challenge
) {
    EncryptedDataResponsePacket packet;
    struct sockaddr_in sender_addr;
    int sender_len = sizeof(sender_addr);

    int received = recvfrom(
        data_sock,
        (char *)&packet,
        sizeof(packet),
        0,
        (struct sockaddr *)&sender_addr,
        &sender_len
    );

    if (received == SOCKET_ERROR) {
        printf("No encrypted data response received\n");
        return -1;
    }

    if (received != sizeof(EncryptedDataResponsePacket)) {
        printf("Invalid encrypted response size ignored\n");
        return -1;
    }

    if (strncmp(packet.magic, ENCRYPTED_DATA_RESPONSE_MAGIC, MAGIC_SIZE) != 0) {
        printf("Invalid encrypted response magic ignored\n");
        return -1;
    }

    EncryptedDataResponseBody body;
    unsigned long long decrypted_len = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            (unsigned char *)&body,
            &decrypted_len,
            NULL,
            packet.ciphertext,
            sizeof(packet.ciphertext),
            NULL,
            0,
            packet.nonce,
            session->rx_key
        ) != 0) {
        printf("Encrypted response authentication failed\n");
        return -1;
    }

    if (decrypted_len != sizeof(EncryptedDataResponseBody)) {
        printf("Invalid encrypted response plaintext size\n");
        return -1;
    }

    if (strncmp(body.magic, DATA_RESPONSE_MAGIC, MAGIC_SIZE) != 0) {
        printf("Invalid encrypted response plaintext magic\n");
        return -1;
    }

    if (strncmp(body.device_id, robot->device_id, DEVICE_ID_SIZE) != 0 ||
        strncmp(body.serial_number, robot->serial_number, SERIAL_SIZE) != 0) {
        printf("Encrypted response identity mismatch ignored\n");
        return -1;
    }

    if (body.challenge_nonce != expected_challenge) {
        printf("Encrypted response challenge mismatch ignored\n");
        return -1;
    }

    if (!is_timestamp_fresh(body.timestamp)) {
        printf("Old encrypted response timestamp ignored\n");
        return -1;
    }

    if (body.response_sequence <= session->last_response_sequence) {
        printf("Old or replayed encrypted response ignored\n");
        return -1;
    }

    session->last_response_sequence = body.response_sequence;

    printf("Valid encrypted robot data received\n");
    printf("Device ID     : %s\n", body.device_id);
    printf("Serial Number : %s\n", body.serial_number);
    printf("Response Seq  : %u\n", body.response_sequence);
    printf("Counter       : %d\n", body.counter);
    printf("Battery       : %.2f\n", body.battery_level);
    printf("Temperature   : %.2f\n", body.temperature);
    printf("Message       : %s\n", body.message);
    printf("------------------------------------------\n");

    return 0;
}

int main() {
    if (sodium_init() < 0) {
        printf("libsodium initialization failed\n");
        return 1;
    }

    TrustedRobot trusted_robots[MAX_TRUSTED_ROBOTS];
    int trusted_count = load_trusted_robots(
        trusted_robots,
        MAX_TRUSTED_ROBOTS
    );

    printf("Loaded trusted robots: %d\n", trusted_count);

    WSADATA wsa_data;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    SOCKET discovery_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (discovery_sock == INVALID_SOCKET) {
        printf("Discovery socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    BOOL broadcast_enable = TRUE;

    if (setsockopt(
            discovery_sock,
            SOL_SOCKET,
            SO_BROADCAST,
            (char *)&broadcast_enable,
            sizeof(broadcast_enable)
        ) == SOCKET_ERROR) {
        printf("SO_BROADCAST failed: %d\n", WSAGetLastError());
        closesocket(discovery_sock);
        WSACleanup();
        return 1;
    }

    DWORD timeout_ms = 3000;

    setsockopt(
        discovery_sock,
        SOL_SOCKET,
        SO_RCVTIMEO,
        (char *)&timeout_ms,
        sizeof(timeout_ms)
    );

    uint64_t discovery_challenge;
    randombytes_buf(&discovery_challenge, sizeof(discovery_challenge));

    DiscoveryRequestPacket discovery_request;
    memset(&discovery_request, 0, sizeof(discovery_request));

    copy_text(discovery_request.magic, MAGIC_SIZE, DISCOVERY_REQUEST_MAGIC);
    discovery_request.challenge_nonce = discovery_challenge;
    discovery_request.timestamp = (uint64_t)time(NULL);

    printf("\nSending robot discovery broadcast...\n");

    int sent = send_discovery_requests(
        discovery_sock,
        &discovery_request
    );

    if (sent == 0) {
        printf("Discovery send failed: %d\n", WSAGetLastError());
        closesocket(discovery_sock);
        WSACleanup();
        return 1;
    }

    DiscoveredRobot robots[MAX_ROBOTS];
    int robot_count = 0;

    printf("Waiting for robot responses...\n\n");

    while (robot_count < MAX_ROBOTS) {
        DiscoveryResponsePacket response;
        struct sockaddr_in sender_addr;
        int sender_len = sizeof(sender_addr);

        int received = recvfrom(
            discovery_sock,
            (char *)&response,
            sizeof(response),
            0,
            (struct sockaddr *)&sender_addr,
            &sender_len
        );

        if (received == SOCKET_ERROR) {
            break;
        }

        if (received != sizeof(DiscoveryResponsePacket)) {
            printf("Invalid discovery response size ignored\n");
            continue;
        }

        if (strncmp(response.body.magic, DISCOVERY_RESPONSE_MAGIC, MAGIC_SIZE) != 0) {
            printf("Invalid discovery response magic ignored\n");
            continue;
        }

        if (response.body.challenge_nonce != discovery_challenge) {
            printf("Discovery challenge mismatch ignored\n");
            continue;
        }

        if (!is_timestamp_fresh(response.body.timestamp)) {
            printf("Old discovery response ignored\n");
            continue;
        }

        int self_signature_ok = crypto_sign_verify_detached(
            response.signature,
            (unsigned char *)&response.body,
            sizeof(DiscoveryResponseBody),
            response.body.public_key
        );

        if (self_signature_ok != 0) {
            printf("Robot self-signature invalid. Ignored.\n");
            continue;
        }

        int trusted_index = find_trusted_robot(
            trusted_robots,
            trusted_count,
            response.body.device_id,
            response.body.serial_number
        );

        int trusted = 0;

        if (trusted_index >= 0) {
            if (is_same_public_key(
                    trusted_robots[trusted_index].public_key,
                    response.body.public_key
                )) {
                trusted = 1;
            } else {
                printf(
                    "WARNING: Robot %s / %s has different public key. Possible spoofing. Ignored.\n",
                    response.body.device_id,
                    response.body.serial_number
                );
                continue;
            }
        }

        if (is_duplicate_robot(
                robots,
                robot_count,
                response.body.device_id,
                response.body.serial_number
            )) {
            continue;
        }

        memset(&robots[robot_count], 0, sizeof(DiscoveredRobot));

        copy_text_field(
            robots[robot_count].device_id,
            DEVICE_ID_SIZE,
            response.body.device_id,
            DEVICE_ID_SIZE
        );
        copy_text_field(
            robots[robot_count].serial_number,
            SERIAL_SIZE,
            response.body.serial_number,
            SERIAL_SIZE
        );
        copy_text_field(
            robots[robot_count].ip_address,
            IP_SIZE,
            response.body.ip_address,
            IP_SIZE
        );

        robots[robot_count].service_port = response.body.service_port;
        memcpy(
            robots[robot_count].public_key,
            response.body.public_key,
            crypto_sign_PUBLICKEYBYTES
        );

        robots[robot_count].trusted = trusted;

        printf(
            "[%d] %s | %s | %s:%d | %s\n",
            robot_count + 1,
            robots[robot_count].device_id,
            robots[robot_count].serial_number,
            robots[robot_count].ip_address,
            robots[robot_count].service_port,
            trusted ? "TRUSTED" : "NEW / UNPAIRED"
        );

        robot_count++;
    }

    if (robot_count == 0) {
        printf("No robots found.\n");
        closesocket(discovery_sock);
        WSACleanup();
        return 1;
    }

    int selected = 0;

    printf("\nSelect robot number: ");
    scanf("%d", &selected);

    if (selected < 1 || selected > robot_count) {
        printf("Invalid selection\n");
        closesocket(discovery_sock);
        WSACleanup();
        return 1;
    }

    DiscoveredRobot selected_robot = robots[selected - 1];

    if (!selected_robot.trusted) {
        char answer[16];

        printf("\nThis robot is not trusted yet.\n");
        printf("Device ID     : %s\n", selected_robot.device_id);
        printf("Serial Number : %s\n", selected_robot.serial_number);
        printf("IP Address    : %s\n", selected_robot.ip_address);
        printf("Port          : %d\n", selected_robot.service_port);

        printf("\nTrust and pair this robot? Type yes to continue: ");
        scanf("%15s", answer);

        if (strcmp(answer, "yes") != 0) {
            printf("Pairing cancelled.\n");
            closesocket(discovery_sock);
            WSACleanup();
            return 1;
        }

        TrustedRobot new_trusted_robot;
        memset(&new_trusted_robot, 0, sizeof(new_trusted_robot));

        copy_text(new_trusted_robot.device_id, DEVICE_ID_SIZE, selected_robot.device_id);
        copy_text(new_trusted_robot.serial_number, SERIAL_SIZE, selected_robot.serial_number);
        memcpy(
            new_trusted_robot.public_key,
            selected_robot.public_key,
            crypto_sign_PUBLICKEYBYTES
        );

        if (save_trusted_robot(&new_trusted_robot) != 0) {
            printf("Failed to save trusted robot.\n");
            closesocket(discovery_sock);
            WSACleanup();
            return 1;
        }

        selected_robot.trusted = 1;

        printf("Robot paired and saved successfully.\n");
    }

    printf(
        "\nSelected trusted robot: %s | %s | %s:%d\n\n",
        selected_robot.device_id,
        selected_robot.serial_number,
        selected_robot.ip_address,
        selected_robot.service_port
    );

    SOCKET data_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (data_sock == INVALID_SOCKET) {
        printf("Data socket failed: %d\n", WSAGetLastError());
        closesocket(discovery_sock);
        WSACleanup();
        return 1;
    }

    setsockopt(
        data_sock,
        SOL_SOCKET,
        SO_RCVTIMEO,
        (char *)&timeout_ms,
        sizeof(timeout_ms)
    );

    struct sockaddr_in robot_data_addr;
    memset(&robot_data_addr, 0, sizeof(robot_data_addr));

    robot_data_addr.sin_family = AF_INET;
    robot_data_addr.sin_port = htons(selected_robot.service_port);

    if (InetPtonA(AF_INET, selected_robot.ip_address, &robot_data_addr.sin_addr) != 1) {
        printf("Invalid robot IP address\n");
        closesocket(data_sock);
        closesocket(discovery_sock);
        WSACleanup();
        return 1;
    }

    SecureSession session;

    if (perform_key_exchange(
            data_sock,
            &robot_data_addr,
            &selected_robot,
            &session
        ) != 0) {
        printf("Secure session setup failed.\n");
        closesocket(data_sock);
        closesocket(discovery_sock);
        WSACleanup();
        return 1;
    }

    while (1) {
        uint64_t data_challenge = 0;

        if (send_encrypted_data_request(
                data_sock,
                &robot_data_addr,
                &selected_robot,
                &session,
                &data_challenge
            ) != 0) {
            Sleep(1000);
            continue;
        }

        receive_encrypted_data_response(
            data_sock,
            &selected_robot,
            &session,
            data_challenge
        );

        Sleep(1000);
    }

    sodium_memzero(&session, sizeof(session));
    closesocket(data_sock);
    closesocket(discovery_sock);
    WSACleanup();

    return 0;
}
