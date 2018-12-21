#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define SUCCESS 0
#define init_header_size 8

//Header field
typedef struct
{
	char header_name[4096];
	char header_value[4096];
} Request_header;

//HTTP Request Header
typedef struct
{
	char http_version[50];
	char http_method[50];
	char http_uri[4096];
	Request_header *headers;
	int header_count;
    int header_capacity;
} Request;

Request* parse(char *buffer, int size,int socketFd);
