#include "log/logging.h"
//#include "utilities/common.h"
#include "handler/response.h"
#include "lisod.h"
#include <fcntl.h>
#include <signal.h>
#define RUNNING_DIR "/home/lzx/computer_network/liso_server/"
//#define DEBUG_VERBOSE 1
//char log_dir[BUF_SIZE] = "/home/lzx/computer_network/liso_server/log/";
//f

int port;
int https_port;

int logging_fd;
char *logging_path;
char *WWW_FOLDER;
char *lock_file;
char *CGI_script;
char *private_key_file;
char *certificate_file;
client_pool pool;
#define USAGE "liso server usage:\n%s http port https port logfile lockfile wwwfolder private key file certificate file\n "

// git test
int main(int argc, char *argv[]){
    int sockfd;
    int https_sockfd;
    SSL_CTX *ssl_context = NULL;
    int client_sockfd;

    if(argc < 9){
        fprintf(stderr, USAGE, argv[0]);
        exit(-1);
    }

    port = atoi(argv[1]);
    https_port = atoi(argv[2]);
    logging_path = argv[3];
    //init_logging();x
    lock_file = argv[4];
    WWW_FOLDER = argv[5];
    CGI_script = argv[6];
    private_key_file = argv[7];
    certificate_file = argv[8];
    #ifdef DEBUG_VERBOSE
    //daemonize();
    #endif
    create_dictionary(WWW_FOLDER, S_IRWXU|S_IRWXG | S_IRWXO|S_IROTH|S_IXOTH);
    //then create socket, bind, listen,
    init_cgi_pool();
    init_logging();
    ssl_init(&ssl_context, private_key_file, certificate_file);
    if((sockfd = create_server_sock(port)) < 0){
        return EXIT_FAILURE;
    }
    //start_listening(sockfd);
    if((https_sockfd = create_ssl_server_sock(https_port, ssl_context)) < 0){
        return EXIT_FAILURE;
    }
    // start_listening(https_sockfd);
    init_pool(sockfd, https_sockfd);
    log_info("HTTP PORT: %d\n", port);
    log_info("HTTPS PORT: %d\n", https_port);
    log_info("www folder:%s\n", WWW_FOLDER);
    start_listening(sockfd);
    start_listening(https_sockfd);
    //to prepare select's based server
    while(1){
        pool.read_fds = pool.master;
        pool.write_fds = pool.master;
        pool.n_ready = select(pool.fd_max + 1, &pool.read_fds, &pool.write_fds, NULL, NULL);

        if(pool.n_ready <= 0){
            if(pool.n_ready < 0){
                //log_error("error in select");
                perror("select:");
                exit(-1);
            }
            continue;
        }
        if(FD_ISSET(sockfd, &pool.read_fds)){
            char remote_ip[INET_ADDRSTRLEN] ={};
            client_sockfd = accept_connection(sockfd, remote_ip);
            if(client_sockfd == -1){
                log_error("error in accept connection");
                continue;
            } else{
                fprintf(stderr, "remote ip:%s\n", remote_ip);
                add_client_to_pool(client_sockfd, remote_ip, HTTP_CLIENT, NULL);
            }
        }else if(FD_ISSET(https_sockfd, &pool.read_fds)){
            char remote_ip[INET_ADDRSTRLEN] = {};
            client_sockfd = accept_connection(https_sockfd, remote_ip);
            if(client_sockfd == -1){
                log_error("error in accept https connection\n");
                SSL_CTX_free(ssl_context);
                continue;
            }else {
                SSL *client_context = NULL;
                wrap_socket_with_ssl(&client_context, ssl_context,https_sockfd, client_sockfd);
                add_client_to_pool(client_sockfd, remote_ip, HTTPS_CLIENT, client_context);
            }
        } else {
            handle_client();
        }
    }
}

int daemonize(){
    int i, lfp, pid = fork();
    char str[256] = {0};
    if (pid < 0) exit(-1);
    if(pid > 0) exit(0);
    setsid();

    for(i = getdtablesize(); i >= 0; i--)   close(i);

    i = open("/dev/null", O_RDWR);
    dup(i);
    dup(i);
    umask(027);
    // chdir(RUNNING_DIR);
    lfp = open(lock_file, O_RDWR|O_CREAT, 0640);

    if(lfp < 0)   exit(-1);
    if(lockf(lfp, F_TLOCK, 0) < 0)   exit(0); /*can not lock*/

    sprintf(str, "%d\n", getpid());
    write(lfp, str, strlen(str));
    //log_info("hello world\n");
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    return 0;
}

/*
 *internal signal handler
 */
void signal_handler(int sig){
    switch(sig){
    case SIGHUP:
        break;
    case SIGTERM:
        break;
    default:
        break;
    }
}
