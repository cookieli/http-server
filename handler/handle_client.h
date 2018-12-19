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

typedef enum client_state{
    INVALID,
    READY_FOR_READ,
    READY_FOR_WRITE,
    WAITING_FOR_CGI,
    CGI_FOR_READ_PIPE,
    CGI_FOR_WRITE_PIPE
}client_state;

typedef struct {
    int listen_fd;
    int ssl_sockfd;
    int fd_max;
    int max_index;//max_index in client_fd
    int n_ready;

    
    int client_fd[FD_SIZE];
    client_type type[FD_SIZE];
    int cgi_client[FD_SIZE]; //knowing the pipe 's corresponding client_fd;

    
    SSL *context[FD_SIZE];

    
    dynamic_storage *client_dbuf[FD_SIZE];
    dynamic_storage *back_up_buffer[FD_SIZE];

    
    int received_headers[FD_SIZE];

    
    char *remote_addr[FD_SIZE];
    client_state state[FD_SIZE];
    int should_be_close[FD_SIZE];

    
    fd_set master;
    fd_set read_fds;
    fd_set write_fds;
} client_pool;

typedef enum http_process_state{
    ERROR,
    CLOSE,
    PERSIST,
    PENDING_REQUEST,
    NOT_ENOUGH_DATA,
    CGI_FOR_WRITE_READY,
    CGI_FOR_READ_READY,
    CGI_FOR_READ_READY_CLOSE,
    CGI_FOR_WRITE_READY_CLOSE
} http_process_state;

extern client_pool pool;

typedef struct host_and_port{
    int port;
    char *host;
} host_and_port;

//void handle_client(int listen_fd);

void init_pool(int listen_fd, int ssl_sockfd);
void add_client_to_pool(int client_sockfd, char *remote_ip, client_type type, SSL *context);
void add_cgi_pipe_to_client_pool(int pipe_fd, int pipe_client, client_state state);
void clear_cgi_pipe_from_pool(int client_fd);
void clear_client_by_client_fd(int client_fd);
void clear_client_by_index(int client_fd, int idx);
void set_received_headers(int client_fd);
void handle_client();
http_process_state handle_corresponding_client(int client_fd, dynamic_storage *client_dbuf, size_t header_len, dynamic_storage *pending_request, host_and_port *hap);


void free_request(Request *request);
int check_client_connection(Request *request);
void get_header_value(Request *request, char *header, char* holder);
char* get_content_length(Request *req);
int get_client_index(int client_fd);

size_t get_client_buffer_offset(int client_fd);
dynamic_storage *get_client_dbuf(int client_fd);
size_t handle_receive_headers(int client_fd, char *client_buffer);
size_t min(size_t a, size_t b);
void reset_client_dbuf_state_by_idx(int idx);
int is_dynamic_request(Request *request);

