#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "logging.h"
//#include <parser/parse.h>
//#define LOG_LENGTH 100
#define LOG_DIC "/home/lzx/computer network/liso_server/log/a.log"
int logging_fd = 0;
char *logging_path = LOG_DIC;

void init_logging(){
    printf("logging file system is ready to init\n");
    logging_fd = open(logging_path, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP);
    if(logging_fd == -1){
        perror("open log file");
        exit(1);
    }
    return;
}

void close_logging(){
    if(close(logging_fd) == -1) {
        fprintf(stderr, "something wrong about close \n");
        exit(2);
    }
    printf("close log file\n");
    return;
}

void log_info(char *fmt, ...){
    va_list args;
    time_t now;
    time(&now);

    va_start(args, fmt);
    //dprintf(logging_fd, "#########log info##############\n");
    //dprintf(logging_fd, "%s", ctime(&now));
    vdprintf(logging_fd, fmt, args);
    //dprintf(logging_fd, "#########log info##############\n");
    va_end(args);
    return;
}

void log_error(char *fmt, ...){
    va_list args;
    time_t now;
    time(&now);

    va_start(args, fmt);
    dprintf(logging_fd, "\n#########log error###########\n");
    dprintf(logging_fd, "%s", ctime(&now));
    vdprintf(logging_fd, fmt, args);
    //vdprintf(logging_fd,"\n");
    //dprintf(logging_fd, "\n#########log error###########\n");
    va_end(args);
    return;
}

void log_debug(char *fmt, ...){
    va_list args;
    time_t now;
    time(&now);

    va_start(args, fmt);
    dprintf(logging_fd, "##########log debug#########\n");
    dprintf(logging_fd, "%s", ctime(&now));
    vdprintf(logging_fd, fmt, args);
    //dprintf(logging_fd, "##########log debug#########\n");
    va_end(args);
    return;
}
void log_request(Request *request){
    int index;
    log_info("Http method %s\n", request->http_method);
    log_info("Http version %s\n", request->http_version);
    log_info("Http Uri %s\n", request->http_uri);
    for(index = 0; index < request->header_count;index++){
        log_info("Request Header\n");
        log_info("Header name %s  Header Value %s\n", request->headers[index].header_name, request->headers[index].header_value);
    }
}
 