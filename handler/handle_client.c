#include "handle_client.h"
//#include "../log/logging.h"
#include "response.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

client_pool pool;
client_pool *p = &pool;

void init_pool(int listen_fd){
    FD_ZERO(&p->master);
    FD_ZERO(&p->read_fds);
    FD_ZERO(&p->write_fds);

    FD_SET(listen_fd, &p->master);

    p->fd_max = listen_fd;
    p->max_index = -1;
    p->n_ready = 0;//this is because server id;

    for(int i = 0; i < FD_SIZE; i++){
        p->client_fd[i] = -1;
        p->buffer_offset[i] = -1;
        p->cur_allocated[i] = 0;
        p->received_headers[i] = -1;
    }
}

void add_client_to_pool(int client_sockfd){
    p->n_ready--;//because server id has been read;
    FD_SET(client_sockfd, &p->master);
    int i;
    for( i = 0; i < FD_SIZE; i++){
        if(p->client_fd[i] == -1){
            p->client_fd[i] = client_sockfd;
            p->client_buffer[i] = (char *)calloc(BUF_SIZE, sizeof(char));
            p->buffer_offset[i] = 0;
            p->cur_allocated[i] = sizeof(char) * BUF_SIZE;
            if (i > p->max_index) p->max_index = i;
            if (p->fd_max < client_sockfd) p->fd_max = client_sockfd;
            break;
        }
    }
    if(i == FD_SIZE){
        fprintf(stderr, "the client is full\n");
    }
    //if(i > p->max_index)   p->max_index = i;
    //if(p->fd_max < client_sockfd)  p->fd_max = client_sockfd;
}

void clear_client_by_index(int client_fd, int idx){
    if(idx > p->max_index){
        fprintf(stderr, "pool don't have %dth client", idx);
        log_error("the pool don't have %dth client", idx);
        return;
    }
    close(client_fd);
    FD_CLR(client_fd, &p->master);
    p->client_fd[idx] = -1;
    free(p->client_buffer[idx]);
    p->cur_allocated[idx] = 0;
    p->received_headers[idx] = -1;
    p->buffer_offset[idx] = -1;
}

size_t get_buffer_offset(int client_fd){

    int i;
    for(i = 0; i < FD_SIZE; i++){
        if(p->client_fd[i] == client_fd){
            return p->buffer_offset[i];
        }
    }
    fprintf(stderr, "don't have this client %d\n", client_fd);
    return -1;
}

size_t get_cur_allocated(int client_fd){
    int i;
    for(i = 0; i < FD_SIZE; i++){
        if(p->client_fd[i] == client_fd){
            return p->cur_allocated[i];
        }
    }
    fprintf(stderr,"dont't have this client %d\n", client_fd);
    return -1;
}

void set_received_headers(int client_fd){
    int i;
    for(i = 0; i < FD_SIZE; i++){
        if(p->client_fd[i] == client_fd){
            p->received_headers[i] = 1;
            return;
        }
    }
}

char* append_request(int client_fd, char *buf, size_t len){
    int i;
    int extension = 0;
    int cur_offset = 0;
    int cur_allocated = 0;
    for (i = 0; i <= p->max_index && p->n_ready > 0 ; i++){
        if(p->client_fd[i] == client_fd){
            cur_offset = p->buffer_offset[i];
            cur_allocated = p->cur_allocated[i];
            if(cur_offset + len > cur_allocated){//we need to dynamic allocate buffer
                while(cur_offset + len -cur_allocated > extension) extension += BUF_SIZE;

                p->client_buffer[i] = (char *)realloc(p->client_buffer[i], extension*sizeof(char));
                if(p->client_buffer[i] == NULL){
                    fprintf(stderr, "can't allocate memory\n");
                }
                p->cur_allocated[i] = cur_allocated + extension;
            }
            strncpy(p->client_buffer[i] + cur_offset, buf, len);
            p->buffer_offset[i] = cur_offset + len;
            break;
        }
    }
    return p->client_buffer[i];
}


void handle_client(int listen_fd){
    char buf[BUF_SIZE];
    memset(buf, 0, BUF_SIZE);
    ssize_t readret = 0;
    char *recv_buf;
    int buf_len;
    int http_respond;
    for(int i = 0; i <= p->max_index; i++){
        int fd = p->client_fd[i];
        if(fd == -1)  continue;

        if(FD_ISSET(fd, &p->read_fds)) {
            fcntl(fd, F_SETFL, O_NONBLOCK);// set client non-blocking

            readret = recv(fd, buf, BUF_SIZE, 0);
            if(readret > 0){
                recv_buf = append_request(fd, buf, readret);

                //now to check this buf have complete request str
                buf_len = get_buffer_offset(fd);
                if((!end_with_crlf(recv_buf)) && buf_len < 2*BUF_SIZE) continue;//it is not a complete request,we need more message;
                set_received_headers(fd);
                http_respond = handle_the_client(fd, recv_buf, buf_len);
                if(http_respond == 0){
                    clear_client_by_index(fd, i);
                }
            }else {
                if(readret == 0){
                    clear_client_by_index(fd, i);
                } else {
                    if(errno == EAGAIN || errno == EWOULDBLOCK){
                        clear_client_by_index(fd, i);
                    }else if(errno = EINTR)  continue;
                }
            }
        }
    }
}

int handle_the_client(int client_fd, char *client_buffer, int len){
    int return_value = 1; //indicate 
    int last_conn = 0;
    Request *request = parse(client_buffer, len, client_fd);
    log_info("print request\n");
    if(request == NULL){
        send_error("400", "Bad Request", client_fd);
        return 0;
    }
    if(request != NULL){
        log_request(request);
        last_conn = check_client_connection(request);
        if(last_conn == 1)  return_value = 0;
        if(check_HTTP_version(request) == -1){
            send_error("505", "HTTP version not supported", client_fd);
            return 0;
        }
        if(strcmp(request->http_method, "GET") == 0){
            do_GET(request, client_fd, last_conn);
            free_request(request);
        }else if(strcmp(request->http_method, "HEAD") == 0){
            do_HEAD(request, client_fd, last_conn);
            free_request(request);
        }else if(strcmp(request->http_method, "POST") == 0){
            do_POST(request, client_fd, last_conn);
            free_request(request);
        }else {
            send_error("501", "Not Implemented", client_fd);
            free_request(request);
        }
    }
    return return_value;
}


void free_request(Request *request){
    free(request->headers);
    free(request);
}

void get_header_value(Request *request, char *header, char *holder){
    Request_header *temp;
    for(int i = 0; i < request->header_count; i++){
        temp = request->headers + i;
        if(strcmp(temp->header_name, header) == 0){
            strcpy(holder, temp->header_value);
            return;
        }
    }
}

int check_client_connection(Request *request){
    Request_header *temp;
    for(int i = 0; i < request->header_count; i++){
        temp  = request->headers + i;
        if(strcmp(temp->header_name, "Connection") == 0){
            if(strcmp(temp->header_value, "Close")){
                return 1;
            }
        }
    }
    return 0;
}