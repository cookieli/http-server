#include "common.h"

void create_dictionary(char *folder, mode_t mode){
    struct stat st = {0};
    if(stat(folder, &st) == -1){
        if(mkdir(folder, mode) < 0){
            fprintf(stderr, "can't mkdir about www folder\n");
            exit(1);
        }
    }
}

int create_server_sock(int port){
    int sock;
    struct sockaddr_in addr;

    if((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1){
        fprintf(stderr, "Failed creating socket.\n");
        return EXIT_FAILURE;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if(bind(sock, (struct sockaddr *)&addr, sizeof(addr))){
        close(sock);
        fprintf(stderr, "Failed binding socket.\n");
        return EXIT_FAILURE;
    }
    return sock;
}

void start_listening(int sock){
    if(listen(sock, 5)){
        close(sock);
        fprintf(stderr, "Error listening on socket. ");
        exit(2);
    }
}

int accept_connection(int listen_fd){
    int client_sock;
    struct sockaddr_in cli_addr;
    socklen_t cli_size;
    cli_size = sizeof(cli_addr);
    client_sock = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_size);
    return client_sock;
}

int is_dir(const char *path){
    struct stat statbuf;
    if(stat(path, &statbuf) != 0)   return 0;
    return S_ISDIR(statbuf.st_mode);
}

int is_regular(const char *path){
    struct stat statbuf;
    if(stat(path, &statbuf) != 0) return 0;
    return S_ISREG(statbuf.st_mode);
}

char *get_extension(const char *filename){
    char *ext = strrchr(filename,'.');
    if(!ext)    exit(-1);
    return ext;
}