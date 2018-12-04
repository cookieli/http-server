#include "log/logging.h"
#include "utilities/common.h"
#include "handler/handle_client.h"
#include "lisod.h"
#include <fcntl.h>
#include <signal.h>
#define RUNNING_DIR "/home/lzx/computer_network/liso_server/"
//#define DEBUG_VERBOSE 1
//char log_dir[BUF_SIZE] = "/home/lzx/computer_network/liso_server/log/";
//fo

int logging_fd;
char *logging_path;
char *WWW_FOLDER;
char *lock_file;
client_pool pool;
#define USAGE "liso server usage:\n%s http port https port logfile lockfile wwwfolder private key file certificate file\n "

// git test
int main(int argc, char *argv[]){
    int sockfd;
    int client_sockfd;

    if(argc < 7){
        fprintf(stderr, USAGE, argv[0]);
        exit(-1);
    }


    int port = atoi(argv[1]);
    logging_path = argv[2];
    //init_logging();x
    lock_file = argv[3];
    WWW_FOLDER = argv[4];
    #ifdef DEBUG_VERBOSE
         daemonize();
    #endif
    create_dictionary(WWW_FOLDER, S_IRWXU|S_IRWXG | S_IRWXO|S_IROTH|S_IXOTH);
    //then create socket, bind, listen,
    init_logging();
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
