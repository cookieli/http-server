//#include "../parser/parse.h"
#include "handle_client.h"

char *construct_error(char *code, char *reason);
void construct_status_line(char *reply, char *code, char *reason);
void construct_header(char *reply, const char *header, const char *value);
void end_header(char *reply);
void reply_to_client_header(char *message, int fd, client_type type, SSL *context);
void reply_to_client_msg_body(char *msg_body, long length, int fd, client_type type, SSL *context);
void send_error(char *code, char *reason, dynamic_storage *dbuf);
int check_HTTP_version(Request *req);
void do_GET(Request *req,  int last_conn, dynamic_storage *dbuf);
void do_HEAD(Request *req, int last_conn, dynamic_storage *dbuf);
void do_POST(Request *req, int last_conn, dynamic_storage *dbuf);
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
    char *envp[CGI_ENVP_LEN];
} CGI_param;




typedef struct{
    int client_fd;
    //for pipe 0 can be read from 1 can be writen to
    int stdin_pipe[2];//parent -> stdin_pipe[1]-stdin_pipe[0]-->child
    int stdout_pipe[2];//child ->stdout_pipe[1] ->stdout_pipe[0]-->parent
    dynamic_storage *cgi_dbuf;//it is where child's stdin read from
    CGI_param *cgi_parameter;
} CGI_executer;

typedef struct{
    CGI_executer *executers[FD_SIZE];
} CGI_pool;

extern CGI_pool *cgi_pool;

CGI_param* init_cgi_param();
void free_cgi_param(CGI_param *pa);
void build_cgi_param(CGI_param *pa, Request *request, host_and_port *hap);
void set_envp_header_with_str(CGI_param *pa, char *envp_var, char *value, int index);
void set_envp_header_with_request(CGI_param *pa, Request *request, char *header, char *envp_var, int index);
char* new_string(char *str);
CGI_executer* init_cgi_executer(CGI_param *pa, int client_fd);
void free_cgi_executer(CGI_executer *exe);
void init_cgi_pool();
void reset_cgi_pool();
void free_cgi_pool();
void add_cgi_executer_to_pool(CGI_executer *exe);
CGI_executer* get_executer_from_pool_by_client(int client_fd);
void clear_cgi_executer_from_pool_by_client(int client_fd);
void execve_error_handler();
void handle_dynamic_request(CGI_param *pa, int client_fd, char *post_body, size_t content_len);
void print_cgi_param(CGI_param *pa);
void print_executer(CGI_executer *exe);
void print_executers_pool();