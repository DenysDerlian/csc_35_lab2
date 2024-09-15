#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <libgen.h>

#define SERVER_PORT 3535
#define BUFSIZE 4096

void check_error(int condition, const char *message) {
    if (condition) {
        perror(message);
        exit(EXIT_FAILURE);
    }
}

// Function to create directories if they do not exist
void create_directories(const char *path) {
    char temp[BUFSIZE];
    snprintf(temp, sizeof(temp), "%s", path);
    char *dir = dirname(temp);

    struct stat st = {0};
    if (stat(dir, &st) == -1) {
        char command[BUFSIZE];
        snprintf(command, sizeof(command), "mkdir -p %s", dir);
        system(command);
    }
}

int main(int argc, char **argv) {
    int c, s, bytes;
    char buf[BUFSIZE];
    struct hostent *h;
    struct sockaddr_in channel;

    if (argc < 3 || (strcmp(argv[2], "MyGet") == 0 && argc != 4)) {
        fprintf(stderr, "Invalid command! Usage: %s server-name MyGet [file-name] | MyLastAccess\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    h = gethostbyname(argv[1]);
    check_error(!h, "gethostbyname failed! Invalid host address.");

    s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    check_error(s < 0, "socket call failed");

    memset(&channel, 0, sizeof(channel));
    channel.sin_family = AF_INET;
    memcpy(&channel.sin_addr.s_addr, h->h_addr, h->h_length);
    channel.sin_port = htons(SERVER_PORT);

    c = connect(s, (struct sockaddr *) &channel, sizeof(channel));
    check_error(c < 0, "connect failed");

    if (strcmp(argv[2], "MyGet") == 0) {
        snprintf(buf, BUFSIZE, "MyGet %s", argv[3]);
    } else if (strcmp(argv[2], "MyLastAccess") == 0) {
        snprintf(buf, BUFSIZE, "MyLastAccess");
    } else {
        fprintf(stderr, "Invalid command. Use MyGet or MyLastAccess.\n");
        close(s);
        exit(EXIT_FAILURE);
    }

    bytes = write(s, buf, strlen(buf) + 1);
    check_error(bytes < 0, "write failed");

    if (strcmp(argv[2], "MyGet") == 0) {
        char file_name[BUFSIZE];
        snprintf(file_name, BUFSIZE, "received_%s", argv[3]);

        // Create directories if they do not exist
        create_directories(file_name);

        // Read the first chunk of data to check if the file exists on the server
        bytes = read(s, buf, BUFSIZE);
        if (bytes <= 0) {
            fprintf(stderr, "Error: No such file or directory on the server\n");
            close(s);
            exit(EXIT_FAILURE);
        }

        int fd = open(file_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        check_error(fd < 0, "open file failed");

        // Write the first chunk of data to the file
        write(fd, buf, bytes);

        // Continue reading and writing the rest of the file
        while ((bytes = read(s, buf, BUFSIZE)) > 0) {
            write(fd, buf, bytes);
        }

        check_error(bytes < 0, "read failed");
        close(fd);
        printf("File %s received from server\n", file_name);
    } else {
        while ((bytes = read(s, buf, BUFSIZE)) > 0) {
            write(1, buf, bytes);
        }

        check_error(bytes < 0, "read failed");
    }

    close(s);
    return 0;
}