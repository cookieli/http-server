//#include "../parser/parse.h"
#include "handle_client.h"

char *construct_error(char *code, char *reason);
void construct_status_line(char *reply, char *code, char *reason);
void construct_header(char *reply, const char *header, const char *value);
void end_header(char *reply);
void reply_to_client_header(char *message, int fd, client_type type, SSL *context);
void reply_to_client_msg_body(char *msg_body, long length, int fd, client_type type, SSL *context);
void send_error(char *code, char *reason, int fd, client_type type, SSL *context);
int check_HTTP_version(Request *req);
void do_GET(Request *req, int fd, int last_conn, client_type type, SSL *context);
void do_HEAD(Request *req, int fd, int last_conn, client_type type, SSL *context);
void do_POST(Request *req, int fd, int last_conn, client_type type, SSL * context);
char *read_file(char *filename, long *len);
char *get_file_mtime(char *filename);
char *get_cur_time();
char *find_MIME(const char *key);
void construct_content_length(char * reply, int num);
int end_with(const char *, const char *);
int end_with_crlf(const char *str);
typedef struct
{
    char key[10];
    char value[50];
} content_type;

#define CGI_ARGS_LEN 2
#define CGI_ENVP_LEN 22
#define CGI_ENVP_INFO_MAXLEN 1024

typedef struct{
    char *filename;
    char *argv[CGI_ARGS_LEN];
    char *envp[CGI_ENVP_INFO_MAXLEN];
} cgi_param;




typedef struct{
    int client_fd;
    int stdin_pipe[2];
    int stdout_pipe[2];
    dynamic_storage *cgi_buf;
    cgi_param *cgi_parameter;
} cgi_executer;

typedef struct{
    cgi_executer *executers[FD_SIZE];
} cgi_pool;

extern cgi_pool *cgi;