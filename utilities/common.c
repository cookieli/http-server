#include "common.h"
#include <arpa/inet.h>
//#include <openssl/ssl.h>

void create_dictionary(char *folder, mode_t mode){
    struct stat st = {0};
    if(stat(folder, &st) == -1){
        if(mkdir(folder, mode) < 0){
            fprintf(stderr, "can't mkdir about www folder\n");
            exit(1);
        }
    }
}
void wrap_socket_with_ssl(SSL **client_context_addr, SSL_CTX *ssl_context, int https_sockfd, int client_sockfd){
    if(((*client_context_addr) = SSL_new(ssl_context)) == NULL){
                close(https_sockfd);
                SSL_CTX_free(ssl_context);
                fprintf(stderr, "Error creating client SSL context. \n");
                exit(EXIT_FAILURE);
            }
            if(SSL_set_fd(*client_context_addr, client_sockfd) == 0){
                close(https_sockfd);
                SSL_free(*client_context_addr);
                SSL_CTX_free(ssl_context);
                fprintf(stderr, "Error accepting client SSL context");
                exit(EXIT_FAILURE);
            }

            if(SSL_accept(*client_context_addr) <= 0){
                close(https_sockfd);
                SSL_free(*client_context_addr);
                SSL_CTX_free(ssl_context);
                fprintf(stderr, "Error accepting (handshake) client SSL context.\n");
                exit(EXIT_FAILURE);
            }
}
int ssl_init(SSL_CTX **ssl_context_addr, char *private_key_file, char *certificate_file){
    SSL_load_error_strings();
    SSL_library_init();

    /*we want to use TLSv1 only */
    if(((*ssl_context_addr) = SSL_CTX_new(TLSv1_server_method())) == NULL){
        fprintf(stderr, "Error creating SSL context.\n");
        return EXIT_FAILURE;
    }
    /* register private key */
    if (SSL_CTX_use_PrivateKey_file((*ssl_context_addr), private_key_file, SSL_FILETYPE_PEM) == 0){
        SSL_CTX_free(*ssl_context_addr);
        fprintf(stderr, "Error associating private key. \n");
        return EXIT_FAILURE;
    }
    /* register public key(certificate) */
    if(SSL_CTX_use_certificate_file(*ssl_context_addr, certificate_file, SSL_FILETYPE_PEM) == 0){
        SSL_CTX_free(*ssl_context_addr);
        fprintf(stderr, "Error associating certificate. \n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
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
        fprintf(stderr, "Failed binding socket. not ssl\n");
        return EXIT_FAILURE;
    }
    return sock;
}

int create_ssl_server_sock(int https_port, SSL_CTX *ssl_context){
    int sock;
    struct sockaddr_in addr;

    if((sock = socket(PF_INET, SOCK_STREAM, 0)) == -1){
        SSL_CTX_free(ssl_context);
        fprintf(stderr, "Failed creating socket. \n");
        return EXIT_FAILURE;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(https_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if(bind(sock, (struct sockaddr *)&addr, sizeof(addr))){
        close(sock);
        SSL_CTX_free(ssl_context);
        fprintf(stderr, "Failed binding socket.ssl\n");
        return EXIT_FAILURE;
    }
    return sock;
}
void start_listening(int sock){
    if(listen(sock, 5)){
        close(sock);
        fprintf(stderr, "Error listening on socket.\n ");
        exit(2);
    }
}

int accept_connection(int listen_fd, char *remote_ip){
    int client_sock;
    struct sockaddr_in cli_addr;
    socklen_t cli_size;
    cli_size = sizeof(cli_addr);
    client_sock = accept(listen_fd, (struct sockaddr *)&cli_addr, &cli_size);
    inet_ntop(AF_INET, &(cli_addr.sin_addr), remote_ip, INET_ADDRSTRLEN);
    fprintf(stderr, "remote ip %s\n", remote_ip);
    return client_sock;
}

/* file api*/

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
/* file API*/

void init_dynamic_storage(dynamic_storage *s, size_t capacity){
    s->buffer = (char *)malloc(sizeof(char) * capacity);
    memset(s->buffer, 0 ,capacity);
    s->offset = 0;
    s->capacity = capacity;
}

void append_storage_dbuf(dynamic_storage *s, char *buf, ssize_t len){
    if(s->offset + len > s->capacity){
        int extension = s->capacity;
        while(s->offset + len > s->capacity + extension) extension *= 2;
        s->buffer = (char *)realloc(s->buffer, extension * sizeof(char));
        s->capacity += extension;
    }
    memcpy(s->buffer+s->offset, buf, len);
    s->offset += len;
}

void reset_dynamic_storage(dynamic_storage *s){
    memset(s->buffer, 0, s->capacity);
    s->offset = 0;
}

void free_dynamic_storage(dynamic_storage *s){
    free(s->buffer);
    free(s);
}

void print_dynamic_storage(dynamic_storage *s){
    if(s == NULL){
        fprintf(stderr, "this dynamic storage is null\n");
        return;
    }
    fprintf(stderr, "dynamic capacity: %ld\n", s->capacity);
    fprintf(stderr, "dynamic offset: %ld\n", s->offset);
    fprintf(stderr, "dynamic buffer: %s\n", s->buffer);
}
