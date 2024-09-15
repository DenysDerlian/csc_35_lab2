#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <time.h>
#include <map>
#include <string>
#include <pthread.h>

#define SERVER_PORT 3535
#define BUF_SIZE 4096
#define QUEUE_SIZE 10

std::map<std::string, time_t> client_last_access;
pthread_mutex_t access_mutex = PTHREAD_MUTEX_INITIALIZER;

void check_error(int condition, const char *message) {
    if (condition) {
        perror(message);
        exit(EXIT_FAILURE);
    }
}

std::string get_client_address(struct sockaddr_in *client_addr) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr->sin_addr), client_ip, INET_ADDRSTRLEN);
    return std::string(client_ip);
}

void* handle_client(void* arg) {
    int client_socket = *((int*)arg);
    free(arg);

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    getpeername(client_socket, (struct sockaddr*)&client_addr, &client_addr_len);

    std::string client_address = get_client_address(&client_addr);
    printf("Client connected: %s\n", client_address.c_str());

    char buf[BUF_SIZE];
    int bytes = read(client_socket, buf, BUF_SIZE);
    check_error(bytes < 0, "read failed");

    time_t current_time = time(NULL);

    static std::map<std::string, time_t> client_last_get_access;

    // Sleep for 5 seconds to simulate a slow server
    sleep(5);

    if (strncmp(buf, "MyGet", 5) == 0) {
        char *file_name = buf + 6; // Skip "MyGet "
        int fd = open(file_name, O_RDONLY);
        if (fd < 0) {
            perror("open failed");
            close(client_socket);
            return NULL;
        }

        while ((bytes = read(fd, buf, BUF_SIZE)) > 0) {
            write(client_socket, buf, bytes);
        }

        close(fd);

        pthread_mutex_lock(&access_mutex);
        client_last_get_access[client_address] = current_time;
        pthread_mutex_unlock(&access_mutex);
    } else if (strncmp(buf, "MyLastAccess", 12) == 0) {
        pthread_mutex_lock(&access_mutex);
        auto it = client_last_get_access.find(client_address);
        if (it != client_last_get_access.end()) {
            snprintf(buf, BUF_SIZE, "Last Access=%s", ctime(&(it->second)));
        } else {
            snprintf(buf, BUF_SIZE, "Last Access=Null\n");
        }
        pthread_mutex_unlock(&access_mutex);
        write(client_socket, buf, strlen(buf) + 1);
    }

    close(client_socket);
    printf("Client disconnected: %s\n", client_address.c_str());
    return NULL;
}

int main() {
    int s, b, l, sa;
    int on = 1;
    struct sockaddr_in channel, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    memset(&channel, 0, sizeof(channel));
    channel.sin_family = AF_INET;
    channel.sin_addr.s_addr = htonl(INADDR_ANY);
    channel.sin_port = htons(SERVER_PORT);

    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    check_error(s < 0, "socket call failed");

    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on));

    b = bind(s, (struct sockaddr *) &channel, sizeof(channel));
    check_error(b < 0, "bind failed");

    l = listen(s, QUEUE_SIZE);
    check_error(l < 0, "listen failed");

    while (1) {
        sa = accept(s, (struct sockaddr *) &client_addr, &client_addr_len);
        check_error(sa < 0, "accept failed");

        int* client_socket = (int*)malloc(sizeof(int));
        *client_socket = sa;

        pthread_t thread;
        pthread_create(&thread, NULL, handle_client, client_socket);
        pthread_detach(thread);
    }

    close(s);
    return 0;
}