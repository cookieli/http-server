#include "../utilities/common.h"
//#include "../parser/parse.h"
#include "../log/logging.h"
#define BUF_SIZE 8192
#define FD_SIZE 8192

typedef enum client_type{
    INVALID_CLIENT,
    HTTP_CLIENT,
    HTTPS_CLIENT
} client_type;

typedef struct {
    int listen_fd;
    int ssl_sockfd;
    int fd_max;
    int max_index;//max_index in client_fd
    int n_ready;
    int client_fd[FD_SIZE];
    client_type type[FD_SIZE];
    SSL *context[FD_SIZE];
    char *client_buffer[FD_SIZE];
    size_t buffer_offset[FD_SIZE];
    size_t cur_allocated[FD_SIZE];
    int received_headers[FD_SIZE];
    char *remote_addr[FD_SIZE];

    fd_set master;
    fd_set read_fds;
    fd_set write_fds;
} client_pool;

extern client_pool pool;

//void handle_client(int listen_fd);

void init_pool(int listen_fd, int ssl_sockfd);
void add_client_to_pool(int client_sockfd, char *remote_ip, client_type type, SSL *context);
void clear_client_by_index(int client_fd, int idx);
size_t get_buffer_offset(int client_fd);
size_t get_cur_allocated(int client_fd);
void set_received_headers(int client_fd);
char *append_request(int client_fd, char *buf, size_t len);
void handle_client();
int handle_the_client(int client_fd, char *client_buffer, int len);
void free_request(Request *request);
int check_client_connection(Request *request);
void get_header_value(Request *request, char *header, char *holder);
