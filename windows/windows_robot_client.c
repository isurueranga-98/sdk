// windows_client/windows_robot_client.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <sodium.h>

#pragma comment(lib, "ws2_32.lib")

#define TRUSTED_FILE "trusted_robots.txt"

#define DISCOVERY_PORT 5005

#define MAGIC_SIZE 8
#define DEVICE_ID_SIZE 32
#define SERIAL_SIZE 32
#define IP_SIZE 32
#define MESSAGE_SIZE 256

#define MAX_ROBOTS 20
#define MAX_TRUSTED_ROBOTS 50

#define DISCOVERY_REQUEST_MAGIC "RDISCOV"
#define DISCOVERY_RESPONSE_MAGIC "RRESPON"
#define DATA_REQUEST_MAGIC "RDATAQ"
#define DATA_RESPONSE_MAGIC "RDATAR"

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
} TrustedRobot;

typedef struct {
    char device_id[DEVICE_ID_SIZE];
    char serial_number[SERIAL_SIZE];
    char ip_address[IP_SIZE];
    uint16_t service_port;
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];
    int trusted;
} DiscoveredRobot;

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

        strncpy(trusted_robots[count].device_id, device_id, DEVICE_ID_SIZE - 1);
        strncpy(trusted_robots[count].serial_number, serial_number, SERIAL_SIZE - 1);

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

    struct sockaddr_in broadcast_addr;
    memset(&broadcast_addr, 0, sizeof(broadcast_addr));

    broadcast_addr.sin_family = AF_INET;
    broadcast_addr.sin_port = htons(DISCOVERY_PORT);
    broadcast_addr.sin_addr.s_addr = INADDR_BROADCAST;

    uint64_t discovery_challenge;
    randombytes_buf(&discovery_challenge, sizeof(discovery_challenge));

    DiscoveryRequestPacket discovery_request;
    memset(&discovery_request, 0, sizeof(discovery_request));

    strncpy(discovery_request.magic, DISCOVERY_REQUEST_MAGIC, MAGIC_SIZE);
    discovery_request.challenge_nonce = discovery_challenge;
    discovery_request.timestamp = (uint64_t)time(NULL);

    printf("\nSending robot discovery broadcast...\n");

    int sent = sendto(
        discovery_sock,
        (const char *)&discovery_request,
        sizeof(discovery_request),
        0,
        (struct sockaddr *)&broadcast_addr,
        sizeof(broadcast_addr)
    );

    if (sent == SOCKET_ERROR) {
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

        uint64_t now = (uint64_t)time(NULL);

        if (response.body.timestamp + 10 < now) {
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

        strncpy(robots[robot_count].device_id, response.body.device_id, DEVICE_ID_SIZE - 1);
        strncpy(robots[robot_count].serial_number, response.body.serial_number, SERIAL_SIZE - 1);
        strncpy(robots[robot_count].ip_address, response.body.ip_address, IP_SIZE - 1);

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

        strncpy(new_trusted_robot.device_id, selected_robot.device_id, DEVICE_ID_SIZE - 1);
        strncpy(new_trusted_robot.serial_number, selected_robot.serial_number, SERIAL_SIZE - 1);
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

    uint32_t last_sequence_number = 0;

    while (1) {
        uint64_t data_challenge;
        randombytes_buf(&data_challenge, sizeof(data_challenge));

        DataRequestPacket request;
        memset(&request, 0, sizeof(request));

        strncpy(request.magic, DATA_REQUEST_MAGIC, MAGIC_SIZE);
        request.challenge_nonce = data_challenge;
        request.timestamp = (uint64_t)time(NULL);

        int data_sent = sendto(
            data_sock,
            (const char *)&request,
            sizeof(request),
            0,
            (struct sockaddr *)&robot_data_addr,
            sizeof(robot_data_addr)
        );

        if (data_sent == SOCKET_ERROR) {
            printf("Data request failed: %d\n", WSAGetLastError());
            Sleep(1000);
            continue;
        }

        DataResponsePacket response;
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
            printf("No data response received\n");
            Sleep(1000);
            continue;
        }

        if (received != sizeof(DataResponsePacket)) {
            printf("Invalid data response size ignored\n");
            Sleep(1000);
            continue;
        }

        if (strncmp(response.body.magic, DATA_RESPONSE_MAGIC, MAGIC_SIZE) != 0) {
            printf("Invalid data response magic ignored\n");
            Sleep(1000);
            continue;
        }

        if (strncmp(response.body.device_id, selected_robot.device_id, DEVICE_ID_SIZE) != 0 ||
            strncmp(response.body.serial_number, selected_robot.serial_number, SERIAL_SIZE) != 0) {
            printf("Robot identity mismatch ignored\n");
            Sleep(1000);
            continue;
        }

        if (response.body.challenge_nonce != data_challenge) {
            printf("Data challenge mismatch ignored\n");
            Sleep(1000);
            continue;
        }

        int verify_result = crypto_sign_verify_detached(
            response.signature,
            (unsigned char *)&response.body,
            sizeof(DataResponseBody),
            selected_robot.public_key
        );

        if (verify_result != 0) {
            printf("Invalid data signature ignored\n");
            Sleep(1000);
            continue;
        }

        if (response.body.sequence_number <= last_sequence_number) {
            printf("Old or replayed data packet ignored\n");
            Sleep(1000);
            continue;
        }

        last_sequence_number = response.body.sequence_number;

        uint64_t now = (uint64_t)time(NULL);

        if (response.body.timestamp + 10 < now) {
            printf("Old data timestamp ignored\n");
            Sleep(1000);
            continue;
        }

        printf("Valid signed robot data received\n");
        printf("Device ID     : %s\n", response.body.device_id);
        printf("Serial Number : %s\n", response.body.serial_number);
        printf("Sequence No   : %u\n", response.body.sequence_number);
        printf("Counter       : %d\n", response.body.counter);
        printf("Battery       : %.2f\n", response.body.battery_level);
        printf("Temperature   : %.2f\n", response.body.temperature);
        printf("Message       : %s\n", response.body.message);
        printf("------------------------------------------\n");

        Sleep(1000);
    }

    closesocket(data_sock);
    closesocket(discovery_sock);
    WSACleanup();

    return 0;
}