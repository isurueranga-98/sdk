// linux_robot/shm_writer.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#define SHM_NAME "/robot_shared_memory"
#define SHM_SIZE 1024
#define MESSAGE_SIZE 256

typedef struct {
    int counter;
    float battery_level;
    float temperature;
    char message[MESSAGE_SIZE];
} RobotSharedData;

int main() {
    int shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);

    if (shm_fd == -1) {
        perror("shm_open failed");
        return 1;
    }

    if (ftruncate(shm_fd, SHM_SIZE) == -1) {
        perror("ftruncate failed");
        close(shm_fd);
        return 1;
    }

    RobotSharedData *data = mmap(
        NULL,
        SHM_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_SHARED,
        shm_fd,
        0
    );

    if (data == MAP_FAILED) {
        perror("mmap failed");
        close(shm_fd);
        return 1;
    }

    int counter = 0;

    while (1) {
        data->counter = counter;
        data->battery_level = 95.0f - (counter % 20);
        data->temperature = 35.0f + (counter % 5);

        snprintf(
            data->message,
            sizeof(data->message),
            "Robot shared memory data. Counter = %d",
            counter
        );

        printf(
            "Shared memory written | counter=%d battery=%.2f temp=%.2f message=%s\n",
            data->counter,
            data->battery_level,
            data->temperature,
            data->message
        );

        counter++;
        sleep(1);
    }

    munmap(data, SHM_SIZE);
    close(shm_fd);

    return 0;
}