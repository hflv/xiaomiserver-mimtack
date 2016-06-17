

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>




#include "apps_lhf.h"



#include "s_apps_lhf.h"
#include <openssl/ssl.h>
static int ssl_sock_init(void);

static int init_client_ip(int *sock,unsigned char ip[4], int port, int type);
static int init_server(int *sock, int port, int type);
static int init_server_long(int *sock, int port,char *ip, int type);
static int do_accept(int acc_sock, int *sock, char **host);
static int host_ip(char *str, unsigned char ip[4]);
static struct hostent *GetHostByName(char *name);


#define SOCKET_PROTOCOL	IPPROTO_TCP











	

int init_client(int *sock, char *host, int port, int type)
	{
	unsigned char ip[4];

	memset(ip, '\0', sizeof ip);
	if (!host_ip(host,&(ip[0])))
		return 0;
	return init_client_ip(sock,ip,port,type);
	}

static int init_client_ip(int *sock, unsigned char ip[4], int port, int type)
	{
	unsigned long addr;
	struct sockaddr_in them;
	int s,i;

	if (!ssl_sock_init()) return(0);

	memset((char *)&them,0,sizeof(them));
	them.sin_family=AF_INET;
	them.sin_port=htons((unsigned short)port);
	addr=(unsigned long)
		((unsigned long)ip[0]<<24L)|
		((unsigned long)ip[1]<<16L)|
		((unsigned long)ip[2]<< 8L)|
		((unsigned long)ip[3]);
	them.sin_addr.s_addr=htonl(addr);

	if (type == SOCK_STREAM)
		s=socket(AF_INET,SOCK_STREAM,SOCKET_PROTOCOL);
	else /* ( type == SOCK_DGRAM) */
		s=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
			
	if (s == INVALID_SOCKET) { perror("socket"); return(0); }

#if defined(SO_KEEPALIVE) && !defined(OPENSSL_SYS_MPE)
	if (type == SOCK_STREAM)
		{
		i=0;
		i=setsockopt(s,SOL_SOCKET,SO_KEEPALIVE,(char *)&i,sizeof(i));
		if (i < 0) { perror("keepalive"); return(0); }
		}
#endif

	if (connect(s,(struct sockaddr *)&them,sizeof(them)) == -1)
		{ closesocket(s); perror("connect"); return(0); }
	*sock=s;
	return(1);
	}

int do_server(int port, int type, int *ret, int (*cb)(char *hostname, int s, unsigned char *context), unsigned char *context)
	{
	int sock;
	char *name = NULL;
	int accept_socket = 0;
	int i;

	if (!init_server(&accept_socket,port,type)) return(0);

	if (ret != NULL)
		{
		*ret=accept_socket;
		/* return(1);*/
		}
  	for (;;)
  		{
		if (type==SOCK_STREAM)
			{
			if (do_accept(accept_socket,&sock,&name) == 0)
				{
				close(accept_socket);
				return(0);
				}
			}
		else
			sock = accept_socket;
		i=(*cb)(name,sock, context);
		if (name != NULL) OPENSSL_free(name);
		if (type==SOCK_STREAM)
			close(sock);
		if (i < 0)
			{
			close(accept_socket);
			return(i);
			}
		}
	}

static int init_server_long(int *sock, int port, char *ip, int type)
	{
	int ret=0;
	struct sockaddr_in server;
	int s= -1;


	if (!ssl_sock_init()) return(0);

	memset((char *)&server,0,sizeof(server));
	server.sin_family=AF_INET;
	server.sin_port=htons((unsigned short)port);
	if (ip == NULL)
		server.sin_addr.s_addr=INADDR_ANY;
	else
/* Added for T3E, address-of fails on bit field (beckman@acl.lanl.gov) */
#ifndef BIT_FIELD_LIMITS
		memcpy(&server.sin_addr.s_addr,ip,4);
#else
		memcpy(&server.sin_addr,ip,4);
#endif
	
		if (type == SOCK_STREAM)
			s=socket(AF_INET,SOCK_STREAM,SOCKET_PROTOCOL);
		else /* type == SOCK_DGRAM */
			s=socket(AF_INET, SOCK_DGRAM,IPPROTO_UDP);

	if (s == INVALID_SOCKET) goto err;
#if defined SOL_SOCKET && defined SO_REUSEADDR
		{
		int j = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
			   (void *) &j, sizeof j);
		}
#endif
	if (bind(s,(struct sockaddr *)&server,sizeof(server)) == -1)
		{
#ifndef OPENSSL_SYS_WINDOWS
		perror("bind");
#endif
		goto err;
		}
	/* Make it 128 for linux */
	if (type==SOCK_STREAM && listen(s,128) == -1) goto err;
	*sock=s;
	ret=1;
err:
	if ((ret == 0) && (s != -1))
		{
		close(s);
		}
	return(ret);
	}
static int ssl_sock_init(void){
	
#ifdef WATT32
		extern int _watt_do_exit;
		_watt_do_exit = 0;
		if (sock_init())
			return (0);
#elif defined(OPENSSL_SYS_WINDOWS)
		if (!wsa_init_done)
			{
			int err;
		  
#ifdef SIGINT
			signal(SIGINT,(void (*)(int))ssl_sock_cleanup);
#endif
			wsa_init_done=1;
			memset(&wsa_state,0,sizeof(wsa_state));
			if (WSAStartup(0x0101,&wsa_state)!=0)
				{
				err=WSAGetLastError();
				BIO_printf(bio_err,"unable to start WINSOCK, error code=%d\n",err);
				return(0);
				}
	
#ifdef OPENSSL_SYS_WIN16
			EnumTaskWindows(GetCurrentTask(),enumproc,0L);
			lpTopWndProc=(FARPROC)GetWindowLong(topWnd,GWL_WNDPROC);
			lpTopHookProc=MakeProcInstance((FARPROC)topHookProc,_hInstance);
	
			SetWindowLong(topWnd,GWL_WNDPROC,(LONG)lpTopHookProc);
#endif /* OPENSSL_SYS_WIN16 */
			}
#elif defined(OPENSSL_SYS_NETWARE) && !defined(NETWARE_BSDSOCK)
	   WORD wVerReq;
	   WSADATA wsaData;
	   int err;
	
	   if (!wsa_init_done)
		  {
	   
# ifdef SIGINT
		  signal(SIGINT,(void (*)(int))sock_cleanup);
# endif
	
		  wsa_init_done=1;
		  wVerReq = MAKEWORD( 2, 0 );
		  err = WSAStartup(wVerReq,&wsaData);
		  if (err != 0)
			 {
			 BIO_printf(bio_err,"unable to start WINSOCK2, error code=%d\n",err);
			 return(0);
			 }
		  }
#endif /* OPENSSL_SYS_WINDOWS */
		return(1);
		

}

static int init_server(int *sock, int port, int type)
	{
	return(init_server_long(sock, port, NULL, type));
	}

static int do_accept(int acc_sock, int *sock, char **host)
	{
	int ret;
	struct hostent *h1,*h2;
	static struct sockaddr_in from;
	int len;
/*	struct linger ling; */

	if (!ssl_sock_init()) return(0);

#ifndef OPENSSL_SYS_WINDOWS
redoit:
#endif

	memset((char *)&from,0,sizeof(from));
	len=sizeof(from);
	/* Note: under VMS with SOCKETSHR the fourth parameter is currently
	 * of type (int *) whereas under other systems it is (void *) if
	 * you don't have a cast it will choke the compiler: if you do
	 * have a cast then you can either go for (int *) or (void *).
	 */
	ret=accept(acc_sock,(struct sockaddr *)&from,(void *)&len);
	if (ret == INVALID_SOCKET)
		{
#if defined(OPENSSL_SYS_WINDOWS) || (defined(OPENSSL_SYS_NETWARE) && !defined(NETWARE_BSDSOCK))
		int i;
		i=WSAGetLastError();
		BIO_printf(bio_err,"accept error %d\n",i);
#else
		if (errno == EINTR)
			{
			/*check_timeout(); */
			goto redoit;
			}
		fprintf(stderr,"errno=%d ",errno);
		perror("accept");
#endif
		return(0);
		}

/*
	ling.l_onoff=1;
	ling.l_linger=0;
	i=setsockopt(ret,SOL_SOCKET,SO_LINGER,(char *)&ling,sizeof(ling));
	if (i < 0) { perror("linger"); return(0); }
	i=0;
	i=setsockopt(ret,SOL_SOCKET,SO_KEEPALIVE,(char *)&i,sizeof(i));
	if (i < 0) { perror("keepalive"); return(0); }
*/

	if (host == NULL) goto end;
#ifndef BIT_FIELD_LIMITS
	/* I should use WSAAsyncGetHostByName() under windows */
	h1=gethostbyaddr((char *)&from.sin_addr.s_addr,
		sizeof(from.sin_addr.s_addr),AF_INET);
#else
	h1=gethostbyaddr((char *)&from.sin_addr,
		sizeof(struct in_addr),AF_INET);
#endif
	if (h1 == NULL)
		{
		BIO_printf(bio_err,"bad gethostbyaddr\n");
		*host=NULL;
		/* return(0); */
		}
	else
		{
		if ((*host=(char *)OPENSSL_malloc(strlen(h1->h_name)+1)) == NULL)
			{
			perror("OPENSSL_malloc");
			return(0);
			}
		BUF_strlcpy(*host,h1->h_name,strlen(h1->h_name)+1);

		h2=GetHostByName(*host);
		if (h2 == NULL)
			{
			BIO_printf(bio_err,"gethostbyname failure\n");
			return(0);
			}
		if (h2->h_addrtype != AF_INET)
			{
			BIO_printf(bio_err,"gethostbyname addr is not AF_INET\n");
			return(0);
			}
		}
end:
	*sock=ret;
	return(1);
	}

int extract_host_port(char *str, char **host_ptr, unsigned char *ip,
	     short *port_ptr)
	{
	char *h,*p;

	h=str;
	p=strchr(str,':');
	if (p == NULL)
		{
		BIO_printf(bio_err,"no port defined\n");
		return(0);
		}
	*(p++)='\0';

	if ((ip != NULL) && !host_ip(str,ip))
		goto err;
	if (host_ptr != NULL) *host_ptr=h;

	if (!extract_port(p,port_ptr))
		goto err;
	return(1);
err:
	return(0);
	}

static int host_ip(char *str, unsigned char ip[4])
	{
	unsigned int in[4]; 
	int i;

		if (sscanf(str,"%u.%u.%u.%u",&(in[0]),&(in[1]),&(in[2]),&(in[3])) == 4)
			{
		for (i=0; i<4; i++)
			if (in[i] > 255)
				{
				BIO_printf(bio_err,"invalid IP address\n");
				goto err;
				}
		ip[0]=in[0];
		ip[1]=in[1];
		ip[2]=in[2];
		ip[3]=in[3];
			}
	return(1);
err:
	return(0);
	}

int extract_port(char *str, short *port_ptr)
	{
	int i;
	struct servent *s;

	i=atoi(str);
	if (i != 0)
		*port_ptr=(unsigned short)i;
	else
		{
		s=getservbyname(str,"tcp");
		if (s == NULL)
			{
			BIO_printf(bio_err,"getservbyname failure for %s\n",str);
			return(0);
			}
		*port_ptr=ntohs((unsigned short)s->s_port);
		}
	return(1);
	}
#define GHBN_NUM	4
	static struct ghbn_cache_st
		{
		char name[128];
		struct hostent ent;
		unsigned long order;
		} ghbn_cache[GHBN_NUM];
	
	static unsigned long ghbn_hits=0L;
	static unsigned long ghbn_miss=0L;
	
	static struct hostent *GetHostByName(char *name)
		{
		struct hostent *ret;
		int i,lowi=0;
		unsigned long low= (unsigned long)-1;
	
		for (i=0; i<GHBN_NUM; i++)
			{
			if (low > ghbn_cache[i].order)
				{
				low=ghbn_cache[i].order;
				lowi=i;
				}
			if (ghbn_cache[i].order > 0)
				{
				if (strncmp(name,ghbn_cache[i].name,128) == 0)
					break;
				}
			}
		if (i == GHBN_NUM) /* no hit*/
			{
			ghbn_miss++;
			ret=gethostbyname(name);
			if (ret == NULL) return(NULL);
			/* else add to cache */
			if(strlen(name) < sizeof ghbn_cache[0].name)
				{
				strcpy(ghbn_cache[lowi].name,name);
				memcpy((char *)&(ghbn_cache[lowi].ent),ret,sizeof(struct hostent));
				ghbn_cache[lowi].order=ghbn_miss+ghbn_hits;
				}
			return(ret);
			}
		else
			{
			ghbn_hits++;
			ret= &(ghbn_cache[i].ent);
			ghbn_cache[i].order=ghbn_miss+ghbn_hits;
			return(ret);
			}
		}





