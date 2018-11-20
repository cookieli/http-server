//#include "../parser/parse.h"

char *construct_error(char *code, char *reason);
void construct_status_line(char *reply, char *code, char *reason);
void construct_header(char *reply, const char *header, const char *value);
void end_header(char *reply);
void reply_to_client_header(char *message, int fd);
void reply_to_client_msg_body(char *msg_body, long length, int fd);
void send_error(char *code, char *reason, int fd);
int check_HTTP_version(Request *req);
void do_GET(Request *req, int fd, int last_conn);
void do_HEAD(Request *req, int fd, int last_conn);
void do_POST(Request *req, int fd, int last_conn);
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

