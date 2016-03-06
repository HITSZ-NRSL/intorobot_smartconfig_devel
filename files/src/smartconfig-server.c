/* 
 * File:   smartconfig-server.c
 * Author: Haoyao Chen
 *
 * Created on Mar. 4, 10:34pm
 * Description: UDP server
 */

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>

char usage[] =
"\n"
"  %s - (C) 2016-2017 MOLMC Ltd. Co.\n"
"  http://www.intorobot.com\n"
"\n"
"  usage: smartconfig-server <options> \n"
"\n"
"  Options:\n"
"      -p --port                : udp socket port of User's App\n"
"\n"
"      -h --help                : Displays this usage screen\n"
"\n";


struct option long_options[] = {
        {"port",     1, 0, 'p'},
        {"help",     0, 0, 'h'},
    };

int main(int argc, char** argv)
{
	int port=5556;
    int sin_len;
    char message[256];
    int iter;
    int option;
    int socket_descriptor;
    struct sockaddr_in sin;
    
    int out_port=5557;
    int socket_out_fd;
    struct sockaddr_in sout;
    
    do {
        option = getopt_long( argc, argv, "p:", long_options, NULL);

        if( option < 0 ) break;

        switch( option )
        {
            case 0 :
                break;

            case ':':
                printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );

            case '?':
                printf("\"%s --help\" for help.\n", argv[0]);
                return( 1 );

            case 'p':
            	port = atoi(optarg);
                break;
        }
        
     }while(1); 
    
    printf("Waiting for data form sender from port %d\n", port);

    bzero(&sin,sizeof(sin));
    sin.sin_family=AF_INET;
    sin.sin_addr.s_addr=htonl(INADDR_ANY);
    sin.sin_port=htons(port);
    sin_len=sizeof(sin);

    socket_descriptor=socket(AF_INET,SOCK_DGRAM,0);
    bind(socket_descriptor,(struct sockaddr *)&sin,sizeof(sin));

    while(1)
    {
    	strcpy(message, "");
        recvfrom(socket_descriptor,message,sizeof(message),0,(struct sockaddr *)&sin,&sin_len);
        printf("Received: %s\n" , message);
        //if(strcmp(message, "{\"command\":\"hello\"}") == 0)
        //	break;
    	//for(iter = 0; iter<12; iter++)
    	//	printf("%02X ", (unsigned char)message[iter]);
    	
    }

    bzero(&sout,sizeof(sout));
    sout.sin_family=AF_INET;
    sout.sin_addr.s_addr=inet_addr("192.168.11.111");
    sout.sin_port=htons(out_port);

    //创建一个 UDP socket
    socket_out_fd = socket(AF_INET,SOCK_DGRAM,0);//IPV4  SOCK_DGRAM 数据报套接字（UDP协议）
    
    //setsockopt(socket_out_fd,SOL_SOCKET,SO_BROADCAST,&so_broadcast,sizeof(so_broadcast));
    
    for(iter=0; iter<2000; iter++)
    {
    	strcpy(message, "{\"status\":\"200\"}");
     	sendto(socket_out_fd, message, strlen(message) + 1, 0,(struct sockaddr *)&sout,sizeof(sout));
    }
  
    close(socket_out_fd);    
    close(socket_descriptor);
    exit(0);

    return (EXIT_SUCCESS);
}
