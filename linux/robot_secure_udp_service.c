// linux_robot/robot_secure_udp_service.c

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
#define DATA_REQUEST_MAGIC "RDATAQ"
#define DATA_RESPONSE_MAGIC "RDATAR"

#pragma pack(push, 1)

typedef struct {
    int counter;
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
    uint64_t challenge_nonce;
    uint64_t timestamp;
} DataRequestPacket;

typedef struct {
    char magic[MAGIC_SIZE];
    char device_id[DEVICE_ID_SIZE];
    char serial_number[SERIAL_SIZE];
    uint32_t sequence_number;
    uint64_t challenge_nonce;
    uint64_t timestamp;
    int32_t counter;
    float battery_level;
    float temperature;
    char message[MESSAGE_SIZE];
} DataResponseBody;

typedef struct {
    DataResponseBody body;
    unsigned char signature[crypto_sign_BYTES];
} DataResponsePacket;

#pragma pack(pop)

typedef struct {
    char device_id[DEVICE_ID_SIZE];
    char serial_number[SERIAL_SIZE];
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    unsigned char private_key[crypto_sign_SECRETKEYBYTES];
} RobotIdentity;

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
        return 1;
    }

    struct sockaddr_in data_addr;
    memset(&data_addr, 0, sizeof(data_addr));

    data_addr.sin_family = AF_INET;
    data_addr.sin_addr.s_addr = INADDR_ANY;
    data_addr.sin_port = htons(DATA_PORT);

    if (bind(data_sock, (struct sockaddr *)&data_addr, sizeof(data_addr)) < 0) {
        perror("data bind failed");
        return 1;
    }

    printf("Robot secure UDP service started\n");
    printf("Device ID      : %s\n", identity.device_id);
    printf("Serial Number  : %s\n", identity.serial_number);
    printf("Discovery port : %d\n", DISCOVERY_PORT);
    printf("Data port      : %d\n", DATA_PORT);

    uint32_t data_sequence = 1;

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
                continue;
            }

            if (strncmp(request.magic, DISCOVERY_REQUEST_MAGIC, MAGIC_SIZE) != 0) {
                printf("Invalid discovery request magic\n");
                continue;
            }

            uint64_t now = (uint64_t)time(NULL);

            if (request.timestamp + 10 < now) {
                printf("Old discovery request ignored\n");
                continue;
            }

            char local_ip[IP_SIZE] = {0};

            if (get_local_ip_for_client(&client_addr, local_ip, sizeof(local_ip)) != 0) {
                strncpy(local_ip, "0.0.0.0", IP_SIZE - 1);
            }

            DiscoveryResponsePacket response;
            memset(&response, 0, sizeof(response));

            strncpy(response.body.magic, DISCOVERY_RESPONSE_MAGIC, MAGIC_SIZE);
            strncpy(response.body.device_id, identity.device_id, DEVICE_ID_SIZE - 1);
            strncpy(response.body.serial_number, identity.serial_number, SERIAL_SIZE - 1);
            strncpy(response.body.ip_address, local_ip, IP_SIZE - 1);

            response.body.service_port = DATA_PORT;
            memcpy(response.body.public_key, identity.public_key, crypto_sign_PUBLICKEYBYTES);
            response.body.challenge_nonce = request.challenge_nonce;
            response.body.timestamp = now;

            crypto_sign_detached(
                response.signature,
                NULL,
                (unsigned char *)&response.body,
                sizeof(DiscoveryResponseBody),
                identity.private_key
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
                identity.device_id,
                local_ip,
                DATA_PORT
            );
        }

        if (FD_ISSET(data_sock, &read_fds)) {
            DataRequestPacket request;
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);

            ssize_t received = recvfrom(
                data_sock,
                &request,
                sizeof(request),
                0,
                (struct sockaddr *)&client_addr,
                &client_len
            );

            if (received != sizeof(DataRequestPacket)) {
                printf("Invalid data request size\n");
                continue;
            }

            if (strncmp(request.magic, DATA_REQUEST_MAGIC, MAGIC_SIZE) != 0) {
                printf("Invalid data request magic\n");
                continue;
            }

            uint64_t now = (uint64_t)time(NULL);

            if (request.timestamp + 10 < now) {
                printf("Old data request ignored\n");
                continue;
            }

            DataResponsePacket response;
            memset(&response, 0, sizeof(response));

            strncpy(response.body.magic, DATA_RESPONSE_MAGIC, MAGIC_SIZE);
            strncpy(response.body.device_id, identity.device_id, DEVICE_ID_SIZE - 1);
            strncpy(response.body.serial_number, identity.serial_number, SERIAL_SIZE - 1);

            response.body.sequence_number = data_sequence++;
            response.body.challenge_nonce = request.challenge_nonce;
            response.body.timestamp = now;

            response.body.counter = shared_data->counter;
            response.body.battery_level = shared_data->battery_level;
            response.body.temperature = shared_data->temperature;

            strncpy(response.body.message, shared_data->message, MESSAGE_SIZE - 1);

            crypto_sign_detached(
                response.signature,
                NULL,
                (unsigned char *)&response.body,
                sizeof(DataResponseBody),
                identity.private_key
            );

            sendto(
                data_sock,
                &response,
                sizeof(response),
                0,
                (struct sockaddr *)&client_addr,
                client_len
            );

            printf(
                "Signed data sent | seq=%u counter=%d battery=%.2f temp=%.2f\n",
                response.body.sequence_number,
                response.body.counter,
                response.body.battery_level,
                response.body.temperature
            );
        }
    }

    close(discovery_sock);
    close(data_sock);
    munmap(shared_data, SHM_SIZE);
    close(shm_fd);

    return 0;
}