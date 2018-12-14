//#include "handle_client.h"
#include "response.h"
#include <string.h>
#include <time.h>
#include "../lisod.h"
#include "../log/logging.h"
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

content_type MIME[5] = {{".html", "text/html"},{".css", "text/css"},{".png","image/png"},{".jpg","image/jpeg"},{".gif", "image/gif"}};


char *WWW_FOLDER;
cgi_pool *cgi;

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

