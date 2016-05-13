/*
 * File:   imlink-response.c
 * Author: Haoyao Chen
 *
 * Created on Jan 20 2016
 *
 * Description: Send response message back to User's App to notice the result of imlink config.
 */


#include <getopt.h>


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h> 
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h> 
#include <sys/param.h> 
#include <net/if.h> 
#include <netinet/in.h> 
#include <net/if_arp.h> 
#undef SOLARIS
#ifdef SOLARIS 
#include <sys/sockio.h> 
#endif 

#define MAXINTERFACES 16 /* 最大接口数 */

char usage[] =
"\n"
"  %s - (C) 2016-2017 MOLMC Ltd. Co.\n"
"  http://www.intorobot.com\n"
"\n"
"  usage: imlink-response <options> \n"
"\n"
"  Options:\n"
"      -s --apssid              : AP's ssid\n"
"      -w --appasswd            : AP's password\n"
"      -b --apbssid             : AP's bssid (mac address)\n"
"      -p --port                : udp socket port of User's App\n"
"      -i --ip                  : ip address of User's Phone\n"
"\n"
"      -h --help                : Displays this usage screen\n"
"\n";


struct option long_options[] = {
        {"apssid",   1, 0, 's'},
        {"appasswd", 1, 0, 'w'},
        {"apbssid",  1, 0, 'b'},
        {"port",     1, 0, 'p'},
        {"ip",       1, 0, 'i'},
        {"help",     0, 0, 'h'},
    };

//get the broadcast ip address
void getNetInfo()
{
  register int fd, intrface, retn = 0; 
  struct ifreq buf[MAXINTERFACES]; /* ifreq结构数组 */
  struct arpreq arp; 
  struct ifconf ifc; 
  if ((fd = socket (AF_INET, SOCK_DGRAM, 0)) >= 0) 
  { 
    ifc.ifc_len = sizeof buf; 
    ifc.ifc_buf = (caddr_t) buf; 
    if (!ioctl (fd, SIOCGIFCONF, (char *) &ifc)) 
    { 
      //获取接口数量信息
      intrface = ifc.ifc_len / sizeof (struct ifreq); 
      printf("interface num is intrface=%d\n",intrface); 
      puts("");
      //根据借口信息循环获取设备IP和MAC地址
      while ( (intrface--) > 0) 
      {
        //获取设备名称
        if(strcmp(buf[intrface].ifr_name,"wlan0") !=0)
            continue;
        //printf ("net device %s\n", buf[intrface].ifr_name); 
        //判断网卡类型 
        if (!(ioctl (fd, SIOCGIFFLAGS, (char *) &buf[intrface]))) 
        { 
          if (buf[intrface].ifr_flags & IFF_PROMISC) 
          { 
            puts ("the interface is PROMISC"); 
            retn++; 
          } 
        } 
        else 
        { 
          char str[256]; 
          sprintf (str, "cpm: ioctl device %s", buf[intrface].ifr_name); 
          perror (str); 
        } 
        //判断网卡状态 
        if (buf[intrface].ifr_flags & IFF_UP) 
        { 
          puts("the interface status is UP"); 
        } 
        else 
        { 
          puts("the interface status is DOWN"); 
        } 
        //获取当前网卡的IP地址 
        if (!(ioctl (fd, SIOCGIFADDR, (char *) &buf[intrface]))) 
        { 
          printf("IP address is:"); 
          puts((char *)inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr)); 
          //printf("\n%d\n"buf[intrface].ifr_addr))->sin_addr.s_addr); 
          //puts (buf[intrface].ifr_addr.sa_data); 
        } 
        else 
        { 
          char str[256]; 
          sprintf (str, "cpm: ioctl device %s", buf[intrface].ifr_name); 
          perror (str); 
        } 
        /* this section can't get Hardware Address,I don't know whether the reason is module driver*/ 
    #ifdef SOLARIS 
        //获取MAC地址
        arp.arp_pa.sa_family = AF_INET; 
        arp.arp_ha.sa_family = AF_INET; 
        ((struct sockaddr_in*)&arp.arp_pa)->sin_addr.s_addr=((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr.s_addr; 
        if (!(ioctl (fd, SIOCGARP, (char *) &arp))) 
        { 
          printf("HW address is:"); 
          //以十六进制显示MAC地址
          printf("%02x:%02x:%02x:%02x:%02x:%02x\n", 
              (unsigned char)arp.arp_ha.sa_data[0], 
              (unsigned char)arp.arp_ha.sa_data[1], 
              (unsigned char)arp.arp_ha.sa_data[2], 
              (unsigned char)arp.arp_ha.sa_data[3], 
              (unsigned char)arp.arp_ha.sa_data[4], 
              (unsigned char)arp.arp_ha.sa_data[5]); 
          puts(""); 
          puts(""); 
        } 
#else 
        if (!(ioctl (fd, SIOCGIFHWADDR, (char *) &buf[intrface]))) 
        { 
          printf("HW address is:"); 
          printf("%02x:%02x:%02x:%02x:%02x:%02x\n", 
              (unsigned char)buf[intrface].ifr_hwaddr.sa_data[0], 
              (unsigned char)buf[intrface].ifr_hwaddr.sa_data[1], 
              (unsigned char)buf[intrface].ifr_hwaddr.sa_data[2], 
              (unsigned char)buf[intrface].ifr_hwaddr.sa_data[3], 
              (unsigned char)buf[intrface].ifr_hwaddr.sa_data[4], 
              (unsigned char)buf[intrface].ifr_hwaddr.sa_data[5]); 
        } 
#endif 
        else 
        { 
          char str[256]; 
          sprintf (str, "cpm: ioctl device %s", buf[intrface].ifr_name); 
          perror (str); 
        } 
        //子网掩码
         if (!(ioctl(fd, SIOCGIFNETMASK, (char *) &buf[intrface])))
        {
              printf("MASK:%s",
                    (char*)inet_ntoa(((struct sockaddr_in*) (&buf[intrface].ifr_addr))->sin_addr));
              puts(""); 
        }
       else
        {
           char str[256];
            sprintf(str, "SIOCGIFADDR ioctl %s", buf[intrface].ifr_name);
            perror(str);
       }
       //广播地址
       if (! (ioctl(fd, SIOCGIFBRDADDR, (char *) &buf[intrface])))
        printf("Broadcast Address:%s\n",
          (char*)inet_ntoa(((struct sockaddr_in*) (&buf[intrface].ifr_addr))->sin_addr));
      puts(""); 
      puts(""); 
      } //while
    } else 
      perror ("cpm: ioctl"); 
  } else 
    perror ("cpm: socket"); 
  close (fd); 
}
//the response packet format is: -s ApSsid, -p ApPasswd, -b bssid(mac)地址，-i ip地址．
//the argument is: (ApSsid+ApPasswd).length+9, mac地址，ip地址，数据总长度．
int main(int argc, char** argv) {

    int i;
    char *string = NULL;
    int port=18266;
    char *ap_ssid = NULL;
    char *ap_passwd = NULL;
    unsigned char ap_bssid[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    int ip[4] = {0xFF, 0xFF, 0xFF, 0xFF};
    char *str_ip = NULL;
    int ssidpasswd_length;
    int option;
    int socket_fd; //套接口描述字
    int iter=0;
	int so_broadcast=1;
    int sent_len;
    unsigned char buf[80];

    struct sockaddr_in my_addr,user_addr;

    getNetInfo();
    return;
    char version[] = "0.1";

/*    if(argc != 11) {
        printf("Please provide all the arguments");
        printf(usage, version );
        return 0; //not enough arguments
    }
*/
    do {
        option = getopt_long( argc, argv, "s:w:b:p:i:", long_options, NULL);

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

            case 's':
                ap_ssid = (char*)malloc(strlen(optarg) + 1);
                strcpy(ap_ssid, optarg);
                break;

            case 'w':
                ap_passwd = (char*)malloc(strlen(optarg) + 1);
                strcpy(ap_passwd, optarg);
                break;

            case 'b':
                sscanf(optarg, "%x:%x:%x:%x:%x:%x", &ap_bssid[0], &ap_bssid[1], &ap_bssid[2], &ap_bssid[3], &ap_bssid[4], &ap_bssid[5]);
                break;

            case 'p':
                port = atoi(optarg);
                break;

            case 'i':
                //str_ip = (char*)malloc(strlen(optarg) + 1);
                str_ip = (char*)malloc(16);
                strcpy(str_ip, optarg);
                sscanf(str_ip, "%d.%d.%d.%d", &ip[0], &ip[1], &ip[2], &ip[3]);
                break;

        }
    }while(1);

    if(ap_passwd!=NULL)  //no password
        ssidpasswd_length = strlen(ap_ssid) + strlen(ap_passwd) + 9;
    else
        ssidpasswd_length = strlen(ap_ssid) + 9;

    my_addr.sin_family=AF_INET;
    my_addr.sin_port=htons(port);
    //change ip to broadcast ip
    //sprintf(str_ip, "%d.%d.%d.255", ip[0], ip[1], ip[2]);
    sprintf(str_ip, "%d.%d.%d.255", ip[0], ip[1], ip[2]);
    printf("the broadcast ip is:%s", str_ip);
    my_addr.sin_addr.s_addr=inet_addr(str_ip);
    bzero(&(my_addr.sin_zero),8);

//    user_addr.sin_family=AF_INET;
//    user_addr.sin_port=htons(port);
//    user_addr.sin_addr.s_addr=inet_addr("192.168.8.1");
//    bzero(&(user_addr.sin_zero),8);
    if((socket_fd=(socket(AF_INET,SOCK_DGRAM,0)))==-1) {
        perror("socket");
        exit(1);
    }
    setsockopt(socket_fd,SOL_SOCKET,SO_BROADCAST,&so_broadcast,sizeof(so_broadcast));
//    if((bind(socket_fd,(struct sockaddr *)&user_addr,
//                        sizeof(struct sockaddr)))==-1) {
//        perror("bind");
//        exit(1);
//    }

    buf[0] = (unsigned char)ssidpasswd_length;

    for(i=0; i<6; i++){
        buf[1+i] = ap_bssid[i];
    }

    for(i=0; i<4; i++){
        buf[7+i] = (char)(ip[i]);
    }

    for(iter=0; iter<=10;iter++)
    {
        if((sent_len =  sendto(socket_fd,buf,11,0,(struct sockaddr *)&my_addr,sizeof(my_addr))) == -1)
        {
            perror("sendto fail");
            //          exit(-1);
        };
        usleep(80000);
    }
    //  printf("%s, %s, %s, %d, %d " , str_ip, ap_ssid, ap_passwd, total_length, ssidpasswd_length);
    for(iter = 0; iter<11; iter++)
        printf("%02X ", (unsigned char)buf[iter]);

    close(socket_fd);
    printf("Messages Sent,terminating\n");

    if(ap_ssid!=NULL)
        free(ap_ssid);

    if(ap_passwd!=NULL)
        free(ap_passwd);

    if(str_ip!=NULL)
        free(str_ip);

    return (EXIT_SUCCESS);
}
