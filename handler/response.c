//#include "handle_client.h"
#include "response.h"
#include <string.h>
#include <time.h>
#include "../lisod.h"
#include "../log/logging.h"
#include <errno.h>
//#include "../parser/parse.h"
//#include <openssl/ssl.h>

const char *crlf = "\r\n";
const char *sp =" ";
const char *http_version = "HTTP/1.1";
const char *status_code_501 = "501";
const char *colon = ": ";
const char *content_length_hdr = "Content-Length";
const char *default_content_type = "application/octet-stream";
const char *server_name = "liso/1.0";
char *CGI_script;
content_type MIME[5] = {{".html", "text/html"},{".css", "text/css"},{".png","image/png"},{".jpg","image/jpeg"},{".gif", "image/gif"}};


char *WWW_FOLDER;
CGI_pool *cgi_pool;

char *construct_error(char *code, char *reason){
    char *reply = (char *)calloc(BUF_SIZE, sizeof(char));
    construct_status_line(reply, code, reason);
    construct_header(reply, content_length_hdr, "0");
    end_header(reply);
    return reply;
}

void construct_status_line(char *reply, char *code, char *reason){
    sprintf(reply, "%s%s%s%s%s%s", http_version, sp, code, sp, reason, crlf);
}

void construct_header(char *reply,const char *header,const char *value){
    strcat(reply, header);
    strcat(reply, colon);
    strcat(reply, value);
    strcat(reply, crlf);
}

void end_header(char *reply){
    strcat(reply, crlf);
}

void construct_msg_body(char *reply, char *msg_body){
    strcat(reply, msg_body);
}
void construct_content_length(char *reply, int num){
    char buffer[20];
    snprintf(buffer, 20, "%d", num);
    construct_header(reply, "content-length", buffer);
}

void reply_to_client_header(char *message, int fd, client_type type, SSL *context){
    if(type == HTTP_CLIENT){
        int err = send(fd, message, strlen(message), 0);
        if(err == -1){
            perror("send");
        }
    } else if(type == HTTPS_CLIENT){
        int ret = SSL_write(context, message, strlen(message));
        if(ret < 0){
            fprintf(stderr, "Error sending to client in header\n");
        }
    }
}

void reply_to_client_msg_body(char *msg_body, long length, int fd, client_type type,SSL *context){
    if(type == HTTP_CLIENT){
        int err = send(fd, msg_body, length, 0);
        if(err == -1){
            perror("send");
        }
    }else if(type == HTTPS_CLIENT){
        int ret = SSL_write(context, msg_body, length);
        if(ret < 0){
            fprintf(stderr, "Error sending to client in msg_body");
        }
    }
}


void send_error(char *code, char *reason, dynamic_storage *dbuf){
    char *reply = construct_error(code, reason);
    //reply_to_client_header(reply, fd, type, context);
    append_storage_dbuf(dbuf, reply, strlen(reply));
}

void do_GET(Request *req, int last_conn, dynamic_storage *dbuf){
    if(check_HTTP_version(req) == -1){
        send_error("505", "HTTP version not supported",dbuf);
        return;
    }
    char full_path[BUF_SIZE];
    char *message_body;
    long length;
    strcpy(full_path, WWW_FOLDER);
    strcat(full_path, req->http_uri);
    if(is_dir(full_path)) {
        strcat(full_path, "/index.html");
    }
    if(!is_regular(full_path)){
        send_error("404","Not Found", dbuf);
        return;
    }
    char *ext = get_extension(full_path);
    char *MIME_type = find_MIME(ext);
    message_body = read_file(full_path,&length);
    char *datestring = get_file_mtime(full_path);
    char *cur_time = get_cur_time();

    char *reply = (char *)calloc(BUF_SIZE, sizeof(char));
    construct_status_line(reply, "200","OK");
    construct_header(reply, "server",server_name);
    construct_header(reply, "date", cur_time);
    construct_header(reply, "content-type",MIME_type);
    //fprintf(stderr, " send message body %s\n", message_body);
    construct_content_length(reply,length);
    //construct_header(reply, "Date", cur_time);
    construct_header(reply, "last-modified", datestring);
    if(last_conn == 1){
        construct_header(reply, "connection", "close");
    } else {
        construct_header(reply, "connection", "Keep-Alive");
    }
    end_header(reply);
    //construct_msg_body(reply, message_body);
    log_info(reply);
    //reply_to_client_header(reply, fd, type, context);
    //reply_to_client_msg_body(message_body, length, fd, type, context);
    append_storage_dbuf(dbuf, reply, strlen(reply));
    append_storage_dbuf(dbuf, message_body, length);
    fprintf(stderr, "has already send http response\n");
    free(message_body);
    free(reply);
    //free(ext);
    //free(MIME_type);
    free(datestring);
    free(cur_time);
}

void do_HEAD(Request *req, int last_conn, dynamic_storage *dbuf){
    if(check_HTTP_version(req) == -1){
        send_error("505", "HTTP version not supported", dbuf);
        return;
    }
    char full_path[BUF_SIZE];
    char *message_body;
    long length;
    strcpy(full_path, WWW_FOLDER);
    strcat(full_path, req->http_uri);
    if(is_dir(full_path)){
        strcat(full_path, "/index.html");
    }
    if(!is_regular(full_path)){
        send_error("404","Not Found", dbuf);
        return;
    }
    char *ext = get_extension(full_path);
    char *MIME_type = find_MIME(ext);
    char *cur_time = get_cur_time();//calloc
    message_body = read_file(full_path, &length);
    free(message_body);
    char *datestring = get_file_mtime(full_path);//calloc
    char *reply = (char *)calloc(BUF_SIZE, sizeof(char));//caloc
    construct_status_line(reply, "200", "OK");
    construct_header(reply, "server", server_name);
    construct_header(reply, "date", cur_time);
    construct_header(reply, "content-type", MIME_type);
    construct_content_length(reply, length);
    construct_header(reply, "last-modified", datestring);
    if(last_conn == 1){
        construct_header(reply, "connection", "close");
    } else {
        construct_header(reply, "connection", "Keep-Alive");
    }
    end_header(reply);
    //reply_to_client_header(reply, fd, type, context);
    append_storage_dbuf(dbuf, reply, strlen(reply));
    free(reply);
    //free(ext);
    //free(MIME_type);
    free(datestring);
    free(cur_time);
}
void do_POST(Request *req, int last_conn, dynamic_storage *dbuf){
    if(check_HTTP_version(req) == -1){
        send_error("505", "HTTP version not supported", dbuf);
        return;
    }
    char content_length[32];
    memset(content_length, 0, sizeof(content_length));
    get_header_value(req, "Content-Length", content_length);
    if(strlen(content_length) == 0){
        send_error("411", "Length-Required", dbuf);
        return;
    }
    char *reply = (char *)calloc(BUF_SIZE, sizeof(char));
    construct_status_line(reply, "200", "OK");
    construct_content_length(reply, 0);
    construct_header(reply, "connection", "close");
    end_header(reply);
    //reply_to_client_header(reply, fd, type, context);
    append_storage_dbuf(dbuf, reply, strlen(reply));
    free(reply);
}

int check_HTTP_version(Request *req){
    char *http_version = req->http_version;
    char *target = "HTTP/1.1";
    if(!strcmp(http_version, target)){
        return 0;
    } 
    return -1;
}

char *read_file(char *filename, long *len){
    FILE *f = fopen(filename, "r+");
    char *message;
    if(f) {
        fseek(f, 0, SEEK_END);
        long length = ftell(f);
        *len = length;
        fseek(f,0,SEEK_SET);
        message = malloc(length);
        fread(message, 1, length, f);
        fclose(f);
        //fprintf(stderr, "%s\n", message);
        return message;
    } else {
        fprintf(stderr, "can't open file.\n");
        return NULL;
    }
}

char *get_file_mtime(char *filename) {
    struct stat attrib;
    stat(filename, &attrib);
    char *date;
    date = (char *)calloc(50, sizeof(char));
    strftime(date, 50, "%a, %d %b %Y %H:%M:%S %Z", gmtime(&(attrib.st_mtime)));
    return date;
}

char *get_cur_time() {
    time_t rawtime;
    //struct tm *info;
    time(&rawtime);
    char *date = (char *)calloc(50, sizeof(char));
    strftime(date, 50, "%a, %d %b %Y %H:%M:%S %Z", localtime(&rawtime));
    return date;
}

char *find_MIME(const char *key){
   for(int i = 0; i < 5; i++){
       if(strcmp(key, MIME[i].key) == 0){
           return MIME[i].value;
       }
   }
   return (char *)default_content_type;
}

int end_with(const char *str, const char *suffix){
    if(!str || !suffix){
        return 0;
    }
    size_t lenstr = strlen(str);
    size_t lensuffix = strlen(suffix);
    if(lensuffix > lenstr)   return 0;
    return strncmp(str + lenstr - lensuffix, suffix, lensuffix) == 0;
}

int end_with_crlf(const char *str) {return end_with(str, crlf);}

/*it is function about cgi set up*/
CGI_param* init_cgi_param(){
    CGI_param *ret = (CGI_param *)malloc(sizeof(CGI_param));
    ret->filename = CGI_script;
    ret->argv[0] = CGI_script;
    ret->argv[1] = NULL;
    for(int i = 0; i < CGI_ENVP_LEN; i++) ret->envp[i] = NULL;
    return ret;
}
void free_cgi_param(CGI_param *pa){
    int i = 0;
    for(; i < CGI_ENVP_LEN; i++){
        if(pa->envp[i] != NULL){
            free(pa->envp[i]);
        }
    }
    free(pa);
}
void build_cgi_param(CGI_param *pa, Request *request, host_and_port *hap){
    int index = 0;
    set_envp_header_with_str(pa, "GATEWAY_INTERFACE", "CGI/1.1", index++);
    set_envp_header_with_str(pa, "SERVER_SOFTWARE", "Liso/1.0", index++);
    set_envp_header_with_str(pa, "SERVER_PROTOCOL", "HTTP/1.1", index++);
    set_envp_header_with_str(pa, "REQUEST_METHOD", request->http_method, index++);
    set_envp_header_with_str(pa, "REQUEST_URI", request->http_uri, index++);
    set_envp_header_with_str(pa, "SCRIPT_NAME", "/cgi", index++);

    char path_info[512]; memset(path_info, 0, 512);
    char query_string[512]; memset(query_string, 0, 512);
    char *split_char;
    if((split_char = strstr(request->http_uri, "?")) !=NULL){
        size_t split_len = split_char - request->http_uri;
        memcpy(query_string, request->http_uri+split_len+1, strlen(request->http_uri) - split_len -1);
        set_envp_header_with_str(pa, "QUERY_STRING", query_string, index++);
        memcpy(path_info, request->http_uri+4, split_len-4);
        set_envp_header_with_str(pa, "PATH_INFO", path_info, index++);
    } else{
        set_envp_header_with_str(pa, "QUERY_STRING", "", index++);
        memcpy(path_info, request->http_uri+4, strlen(request->http_uri) -4);
        set_envp_header_with_str(pa, "PATH_INFO", path_info, index++);
    }

    set_envp_header_with_request(pa, request, "Content-Length", "CONTENT_LENGTH", index++);
    set_envp_header_with_request(pa, request, "Content-Type", "CONTENT_TYPE", index++);
    set_envp_header_with_request(pa, request, "Accept", "HTTP_ACCEPT", index++);
    set_envp_header_with_request(pa, request, "Referer", "HTTP_REFERER", index++);
    set_envp_header_with_request(pa, request, "Accept-Encoding", "HTTP_ACCEPT_ENCODING", index++);
    set_envp_header_with_request(pa, request, "Accept-Language","HTTP_ACCEPT_LANGUAGE", index++);
    set_envp_header_with_request(pa, request, "Accept_Charset", "HTTP_ACCEPT_CHARSET", index++);
    set_envp_header_with_request(pa, request, "Cookie", "HTTP_COOKIE", index++);
    set_envp_header_with_request(pa, request, "User-Agent", "HTTP_USER-AGENT", index++);
    set_envp_header_with_request(pa, request, "Host", "HTTP_HOST", index++);
    set_envp_header_with_request(pa, request, "Connection", "HTTP_CONNECTION", index++);

    set_envp_header_with_str(pa, "REMOTE_ADDR", hap->host, index++);
    char port_str[8];
    memset(port_str, 0, 8);
    sprintf(port_str, "%d", hap->port);
    set_envp_header_with_str(pa, "SERVER_PORT", port_str, index++);
    pa->envp[index++] = NULL;
}

void set_envp_header_with_str(CGI_param *pa, char *envp_var, char *value, int index){
    char buf[CGI_ENVP_INFO_MAXLEN];
    memset(buf, 0, CGI_ENVP_INFO_MAXLEN);
    sprintf(buf, "%s=%s", envp_var, value);
    pa->envp[index] = new_string(buf);
}

void set_envp_header_with_request(CGI_param *pa, Request *request, char *header, char *envp_var,  int index){
    char buf[CGI_ENVP_INFO_MAXLEN];
    char value[CGI_ENVP_INFO_MAXLEN];
    memset(buf, 0, CGI_ENVP_INFO_MAXLEN);
    memset(value, 0, CGI_ENVP_INFO_MAXLEN);
    get_header_value(request, header, value);
    sprintf(buf, "%s=%s", envp_var, value);
    pa->envp[index] = new_string(buf);
}
char* new_string(char *str){
    char *ret = (char *)malloc(strlen(str) + 1);
    memcpy(ret, str, strlen(str)+1);
    return ret;
}

CGI_executer* init_cgi_executer(CGI_param *pa, int client_fd){
    CGI_executer *exe = (CGI_executer *)malloc(sizeof(CGI_executer));
    exe->client_fd = client_fd;
    exe->cgi_parameter = pa;
    init_dynamic_storage(exe->cgi_dbuf, BUF_SIZE);
    return exe;
}
void free_cgi_executer(CGI_executer *exe){
    free_cgi_param(exe->cgi_parameter);
    free_dynamic_storage(exe->cgi_dbuf);
    free(exe);
}
void init_cgi_pool(){
    cgi_pool = (CGI_pool *)malloc(sizeof(CGI_pool));
    for(int i = 0; i < FD_SIZE; i++){
        cgi_pool->executers[i] =NULL;
    }
}

void add_cgi_executer_to_pool(CGI_executer *exe){
    int i;
    for(i = 0; i < FD_SIZE; i++){
        if(cgi_pool->executers[i] == NULL){
            cgi_pool->executers[i] = exe;
            break;
        }
    }
    if (i == FD_SIZE){
        fprintf(stderr,"in add_cgi_executer_to_pool: cgi_pool slot is full\n");
    }
}

CGI_executer *get_executer_from_pool_by_client(int client_fd){
    int i = 0;
    for(; i < FD_SIZE; i++){
        if(cgi_pool->executers[i] != NULL && cgi_pool->executers[i]->client_fd == client_fd){
            return cgi_pool->executers[i];
        }
    }
    fprintf(stderr, "can't find corresponding executer\n");
    return NULL;
}

void clear_cgi_executer_from_pool_by_client(int client_fd){
    int i;
    for(; i < FD_SIZE; i++){
        if(cgi_pool->executers[i] != NULL && cgi_pool->executers[i]->client_fd == client_fd){
            free_cgi_executer(cgi_pool->executers[i]);
            cgi_pool->executers[i] =NULL;
            break;
        }
    }
}

void free_cgi_pool(){
    int i;
    for(i = 0; i < FD_SIZE; i++){
        if(cgi_pool->executers[i] != NULL){
            free_cgi_executer(cgi_pool->executers[i]);
        }
    }
    free(cgi_pool);
}



void execve_error_handler()
{
    switch (errno)
    {
        case E2BIG:
            fprintf(stderr, "The total number of bytes in the environment \
(envp) and argument list (argv) is too large.\n");
            return;
        case EACCES:
            fprintf(stderr, "Execute permission is denied for the file or a \
script or ELF interpreter.\n");
            return;
        case EFAULT:
            fprintf(stderr, "filename points outside your accessible address \
space.\n");
            return;
        case EINVAL:
            fprintf(stderr, "An ELF executable had more than one PT_INTERP \
segment (i.e., tried to name more than one \
interpreter).\n");
            return;
        case EIO:
            fprintf(stderr, "An I/O error occurred.\n");
            return;
        case EISDIR:
            fprintf(stderr, "An ELF interpreter was a directory.\n");
            return;
        case ELIBBAD:
            fprintf(stderr, "An ELF interpreter was not in a recognised \
format.\n");
            return;
        case ELOOP:
            fprintf(stderr, "Too many symbolic links were encountered in \
resolving filename or the name of a script \
or ELF interpreter.\n");
            return;
        case EMFILE:
            fprintf(stderr, "The process has the maximum number of files \
open.\n");
            return;
        case ENAMETOOLONG:
            fprintf(stderr, "filename is too long.\n");
            return;
        case ENFILE:
            fprintf(stderr, "The system limit on the total number of open \
files has been reached.\n");
            return;
        case ENOENT:
            fprintf(stderr, "The file filename or a script or ELF interpreter \
does not exist, or a shared library needed for \
file or interpreter cannot be found.\n");
            return;
        case ENOEXEC:
            fprintf(stderr, "An executable is not in a recognised format, is \
for the wrong architecture, or has some other \
format error that means it cannot be \
executed.\n");
            return;
        case ENOMEM:
            fprintf(stderr, "Insufficient kernel memory was available.\n");
            return;
        case ENOTDIR:
            fprintf(stderr, "A component of the path prefix of filename or a \
script or ELF interpreter is not a directory.\n");
            return;
        case EPERM:
            fprintf(stderr, "The file system is mounted nosuid, the user is \
not the superuser, and the file has an SUID or \
SGID bit set.\n");
            return;
        case ETXTBSY:
            fprintf(stderr, "Executable was open for writing by one or more \
processes.\n");
            return;
        default:
            fprintf(stderr, "Unkown error occurred with execve().\n");
            return;
    }
}
/**************** END UTILITY FUNCTIONS ***************/


void handle_dynamic_request(CGI_param *pa, int client_fd, char *post_body, size_t content_len){
    CGI_executer *exe = init_cgi_executer(pa, client_fd);
    append_storage_dbuf(exe->cgi_dbuf, post_body, content_len);
    add_cgi_executer_to_pool(exe);
    pid_t pid;

    if(pipe(exe->stdin_pipe) < 0){
        fprintf(stderr, "Error piping for stdin.\n");
        exit(-1);
    }

    if(pipe(exe->stdout_pipe) < 0){
        fprintf(stderr, "Error piping for stdout. \n");
    }

    pid = fork();

    if(pid < 0){
        fprintf(stderr, "Something really bad happened when fork()ing.\n");
        exit(-1);
    }

    if(pid == 0){
        close(exe->stdout_pipe[0]);
        close(exe->stdin_pipe[1]);
        dup2(exe->stdout_pipe[1], fileno(stdout));
        dup2(exe->stdin_pipe[0], fileno(stdin));

        if(execve(pa->filename, pa->argv, pa->envp)){
            execve_error_handler();
            fprintf(stderr, "Error executing execve syscall.\n");
            exit(-1);
        }
    }

    if(pid > 0){
        close(exe->stdout_pipe[1]);
        close(exe->stdin_pipe[0]);
    }
}
