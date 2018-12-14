//#include "handle_client.h"
//#include "../log/logging.h"
#include "response.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
//#include <openssl/ssl.h>

client_pool pool;
client_pool *p = &pool;

void init_pool(int listen_fd, int ssl_sockfd){
    FD_ZERO(&p->master);
    FD_ZERO(&p->read_fds);
    FD_ZERO(&p->write_fds);
    p->listen_fd = listen_fd;
    p->ssl_sockfd = ssl_sockfd;
    FD_SET(listen_fd, &p->master);
    FD_SET(ssl_sockfd, &p->master);
    p->fd_max = (listen_fd > ssl_sockfd ? listen_fd: ssl_sockfd);
    p->max_index = -1;
    p->n_ready = 0;//this is because server id;

    for(int i = 0; i < FD_SIZE; i++){
        p->client_fd[i] = -1;
        p->received_headers[i] = -1;
        p->type[i] = INVALID_CLIENT;
        p->context[i] = NULL;
        p->state[i] = INVALID;
        p->remote_addr[i] = NULL;
        p->should_be_close[i] = 0;
        p->client_dbuf[i] = NULL;
        p->back_up_buffer[i] = NULL;
    }
}

void add_client_to_pool(int client_sockfd, char *remote_ip, client_type type, SSL *context){
    p->n_ready--;//because server id has been read;
    FD_SET(client_sockfd, &p->master);
    int i;
    for( i = 0; i < FD_SIZE; i++){
        if(p->client_fd[i] == -1){
            p->client_fd[i] = client_sockfd;
            p->type[i] = type;
            p->state[i] = READY_FOR_READ;
            p->context[i] = context;
            p->remote_addr[i] = remote_ip;
            p->client_dbuf[i] = (dynamic_storage *)malloc(sizeof(dynamic_storage));
            init_dynamic_storage(p->client_dbuf[i], BUF_SIZE);
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
    p->received_headers[idx] = -1;
    p->state[idx] = INVALID;
    p->should_be_close[idx] = 0;
    p->type[idx] = INVALID_CLIENT;
    p->context[idx] = NULL;
    if(p->client_dbuf[idx] != NULL){
        free_dynamic_storage(p->client_dbuf[idx]);
    }
    if(p->back_up_buffer[idx] != NULL){
        free_dynamic_storage(p->back_up_buffer[idx]);
    }
    p->client_dbuf[idx] = NULL;
    p->back_up_buffer[idx] = NULL;
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

char* get_content_length(Request *req){
    char *content_length;
    content_length = (char *)malloc(32 * sizeof(char));
    memset(content_length, 0, 32);
    get_header_value(req, "Content-Length", content_length);
    return content_length;
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

size_t get_client_buffer_offset(int client_fd){
    int i;
    for(i = 0; i <= p->max_index; i++){
        if(client_fd == p->client_fd[i] && p->client_dbuf[i] != NULL){
            return p->client_dbuf[i]->offset;
        }
    }
    fprintf(stderr, "can't find client fd");
    return -1;
}

size_t handle_receive_headers(int client_fd, char *client_buffer){
    char *header_end_id = "\r\n\r\n";
    char *header_end = strstr(client_buffer, header_end_id);
    size_t buf_len = get_client_buffer_offset(client_fd);
    if(header_end == NULL){
        if(buf_len < BUF_SIZE)  return 0;
        else                    return -1;
    } else{
        return (header_end - client_buffer) + strlen(header_end_id);
    }
}

void handle_client(){
    char buf[BUF_SIZE];
    memset(buf, 0,  BUF_SIZE);
    ssize_t readret = 0;
    size_t header_len = 0;
    http_process_state result;
    for(int i = 0; i <= p->max_index; i++){
        int fd = p->client_fd[i];
        if(fd == -1) continue;

        if(FD_ISSET(fd, &p->read_fds) || (p->back_up_buffer[i] != NULL && p->state[i] == READY_FOR_READ)){
            if(p->back_up_buffer[i] != NULL){
                append_storage_dbuf(p->client_dbuf[i], p->back_up_buffer[i]->buffer, p->back_up_buffer[i]->offset);
                free(p->back_up_buffer[i]);
                p->back_up_buffer[i] = NULL;
            }
            if(FD_ISSET(fd, &p->read_fds)){
                p->n_ready --;
                if(p->type[i] == HTTP_CLIENT){
                    readret = recv(fd, buf, BUF_SIZE, 0);
                }
                if(p->type[i] == HTTPS_CLIENT){
                    readret = SSL_read(p->context[i], buf, BUF_SIZE);
                }
                if(readret <= 0){
                    if(readret < 0 && errno == EINTR)  continue;
                    clear_client_by_index(fd, i);
                    continue;
                }else {
                    append_storage_dbuf(p->client_dbuf[i], buf, readret);
                }
            }
            header_len = handle_receive_headers(p->client_fd[i], p->client_dbuf[i]->buffer);
            if(header_len == 0)  continue;
            if(header_len == -1){
                fprintf(stderr, "header length is larger than buf_size\n");
                clear_client_by_index(fd, i);
            }
            dynamic_storage *pending_request = (dynamic_storage *)malloc(sizeof(dynamic_storage));
            init_dynamic_storage(pending_request, BUF_SIZE);
            result = handle_corresponding_client(fd, p->client_dbuf[i], header_len, pending_request);
            if(pending_request->offset == 0){
                free_dynamic_storage(pending_request);
                p->back_up_buffer[i] = NULL;
            } else{
                p->back_up_buffer[i] = pending_request;
            }
            switch(result){
            case(ERROR):
                send_error("500", "Internal Server Error", p->client_dbuf[i]);
            case(CLOSE):
                p->should_be_close[i] = 1;
                    //break;
            case(PERSIST):
                p->state[i] = READY_FOR_WRITE;
                break;
            case(NOT_ENOUGH_DATA):
                continue;
            default:
                break;
            }
        }
        if(FD_ISSET(fd, &p->write_fds) && p->state[i] == READY_FOR_WRITE){
            fprintf(stderr, "server will send response to client %d\n", fd);
            dynamic_storage *storage_dbuf = p->client_dbuf[i];
            size_t send_granularity = BUF_SIZE;
            size_t send_len = min(send_granularity, storage_dbuf->offset - storage_dbuf->send_offset);
            size_t send_bytes;
            if (p->type[i] == HTTP_CLIENT){
                send_bytes = send(fd, storage_dbuf->buffer+storage_dbuf->send_offset, send_len, 0);
            } else {
                send_bytes = SSL_write(p->context[i], storage_dbuf->buffer+storage_dbuf->send_offset, send_len);
            }
            fprintf(stderr, "send granularity: %ld\n", send_granularity);
            fprintf(stderr, "send bytes: %ld\n", send_bytes);
            storage_dbuf->send_offset += send_bytes;
            if(storage_dbuf->send_offset >= storage_dbuf->offset){
                fprintf(stderr, "have already sent all bytes to client \n");
                reset_client_dbuf_state_by_idx(i);
                p->received_headers[i] = 0;
                p->remote_addr[i] = NULL;
                p->state[i] = READY_FOR_READ;
                if(p->should_be_close[i])     clear_client_by_index(fd, i);
                p->n_ready--;
            }
            // p->n_ready--;
        }
    }
}

size_t min(size_t a, size_t b){
    if (a <= b)  return a;
    else         return b;
}

void reset_client_dbuf_state_by_idx(int idx){
    if(p->client_dbuf[idx] != NULL){
        reset_dynamic_storage(p->client_dbuf[idx]);
    }
}

http_process_state handle_corresponding_client(int client_fd, dynamic_storage *client_dbuf, size_t header_len, dynamic_storage *pending_request){
    http_process_state return_value = PERSIST;
    int last_conn = 0;
    Request *request = NULL;
    request = parse(client_dbuf->buffer, (int)header_len, client_fd);
    log_info("print request\n");
    if(request == NULL){
        send_error("400", "Bad Request", client_dbuf);
        return CLOSE;
    }
    if(request != NULL){
        log_request(request);
        last_conn = check_client_connection(request);
        if(last_conn == 1) return_value = CLOSE;
        if(check_HTTP_version(request) == -1){
            send_error("505", "HTTP version not supported", client_dbuf);
            return CLOSE;
        }
        size_t content_len = 0;
        if(strcmp(request->http_method, "POST") == 0){
            char *content_length_str = get_content_length(request);
            if(strlen(content_length_str) == 0){
                send_error("411", "Length-Required", client_dbuf);
                free(request);
                return CLOSE;
            }
            content_len = atoi(content_length_str);
            free(content_length_str);
            fprintf(stderr, "in handle_corresponding_client: content-length: %ld\n", content_len);
            if(content_len < 0){
                fprintf(stderr, "error with content length\n");
                send_error("411", "Length-Required", client_dbuf);
                free_request(request);
                return CLOSE;
            }
            if(header_len + content_len > client_dbuf->offset){
                free_request(request);
                return NOT_ENOUGH_DATA;
            }else if(header_len + content_len < client_dbuf->offset){
                //we have pending requeset because of pipeline
                size_t request_len = header_len + content_len;
                append_storage_dbuf(pending_request, client_dbuf->buffer + request_len, client_dbuf->offset - request_len);
            }
        } else if(strcmp(request->http_method, "GET") == 0 || strcmp(request->http_method, "HEAD") == 0){
            if(client_dbuf->offset > header_len){
                append_storage_dbuf(pending_request, client_dbuf->buffer +header_len, client_dbuf->offset - header_len);
            }
        } else {
            send_error("501", "Not-Implemented", client_dbuf);
            free_request(request);
            return CLOSE;
        }

        if(!strcmp(request->http_method, "GET")){
            reset_dynamic_storage(client_dbuf);
            do_GET(request, last_conn, client_dbuf);
        }else if(!strcmp(request->http_method, "HEAD")){
            reset_dynamic_storage(client_dbuf);
            do_HEAD(request, last_conn, client_dbuf);
        }else if(!strcmp(request->http_method, "POST")){
            reset_dynamic_storage(client_dbuf);
            do_POST(request, last_conn, client_dbuf);
        }
        free_request(request);
        return return_value;
    }
    return return_value;
}
