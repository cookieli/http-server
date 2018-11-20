#include "log/logging.h"
#include "utilities/common.h"
#include "handler/handle_client.h"
#include "lisod.h"
//char log_dir[BUF_SIZE] = "/home/lzx/computer_network/liso_server/log/";
//fok
int logging_fd;
char *logging_path;
char *WWW_FOLDER;
client_pool pool;
#define USAGE "liso server usage:\n%s http port logfile wwwfolder\n "
// git test
int main(int argc, char *argv[]){
    int sockfd;
    int client_sockfd;

    if(argc < 4){
        fprintf(stderr, USAGE, argv[0]);
        exit(-1);
    }
    int port = atoi(argv[1]);
    logging_path = argv[2];
    init_logging();
    WWW_FOLDER = argv[3];
    create_dictionary(WWW_FOLDER, S_IRWXU|S_IRWXG | S_IRWXO|S_IROTH|S_IXOTH);
    //then create socket, bind, listen,
    sockfd = create_server_sock(port);
    init_pool(sockfd);
    log_info("HTTP PORT: %d\n", port);
    log_info("www folder:%s\n", WWW_FOLDER);
    start_listening(sockfd);
    //to prepare select's based server
    while(1){
        pool.read_fds = pool.master;
        pool.n_ready = select(pool.fd_max + 1, &pool.read_fds, NULL, NULL, NULL);

        if(pool.n_ready <= 0){
            if(pool.n_ready < 0){
                //log_error("error in select");
                perror("select:");
                exit(-1);
            }
            continue;
        }
        if(FD_ISSET(sockfd, &pool.read_fds)){
            client_sockfd = accept_connection(sockfd);
            if(client_sockfd == -1){
                log_error("error in accept connection");
                continue;
            } else{
                add_client_to_pool(client_sockfd);
            }
        }else {
            handle_client(sockfd);
        }
    }
}

