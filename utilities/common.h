#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <openssl/ssl.h>
void create_dictionary(char *, mode_t);
int create_server_sock(int port);
void start_listening(int sock);
int accept_connection(int listen_fd, char *remote_ip);
int is_dir(const char *path);
int is_regular(const char *path);
char *get_extension(const char *filename);
int create_ssl_server_sock(int https_port, SSL_CTX *ssl_context);
int ssl_init(SSL_CTX **ssl_context, char *private_key_file, char *certificate_file);
void wrap_socket_with_ssl(SSL **client_context, SSL_CTX *ssl_context, int https_sockfd, int client_sockfd);