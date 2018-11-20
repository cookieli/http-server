#ifndef LOGGING_H
#define LOGGING_H
#include "../parser/parse.h"
#define LOG_LENGTH 100
void init_logging();
void close_logging();
void log_info(char *fmt, ...);
void log_error(char *fmt, ...);
void log_debug(char *fmt, ...);
void log_request(Request *request);
extern int logging_fd;
extern char *logging_path;

#endif