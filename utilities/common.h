#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
void create_dictionary(char *, mode_t);
int create_server_sock(int port);
void start_listening(int sock);
int accept_connection(int listen_fd);
int is_dir(const char *path);
int is_regular(const char *path);
char *get_extension(const char *filename);