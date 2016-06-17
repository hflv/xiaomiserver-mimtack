  

#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/e_os2.h>
#include <sys/types.h>
#include <openssl/lhash.h>
#include <openssl/bn.h>

#include "apps_lhf.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/ocsp.h>

#include <openssl/dh.h>
#include <sys/socket.h>

#include <openssl/rsa.h>
#include <openssl/ssl.h>


#include <openssl/srp.h>

#include "s_apps_lhf.h"
#include "loginresponse.h"
#include <sys/msg.h> 
#include <sys/ipc.h>






#define PORT_LHF 443
#define XIAOMIACCOUNT "123.125.102.21"
#define TestCAfile "rootca_cert.pem"
#define ServerCertfile "server_cert.pem"
#define ServerKeyfile "server_key.pem"

#define certchain "xiaomichain_cert.pem"
#define certchainkey "xiaomi_key.pem"


#ifdef FIONBIO
	static int s_nbio=0;
#endif

#undef BUFSIZZ
#define BUFSIZZ	16*1024
static int bufsize=BUFSIZZ;
static int accept_socket= -1;
extern int verify_depth, verify_return_error;

//static char *cipher="ECDHE-RSA-RC4-SHA";
static char *cipher=NULL;

static int s_server_verify=SSL_VERIFY_NONE;
static int s_server_session_id_context = 1; /* anything will do */
static const *s_cert_file=ServerCertfile,*s_key_file=ServerKeyfile;
static SSL_CTX *ctx=NULL;
#ifndef OPENSSL_NO_ENGINE
static char *engine_id=NULL;
#endif
static int s_quiet=0;
static BIO *bio_s_out=NULL;

#ifndef OPENSSL_NO_ECDH
	char *named_curve = NULL;
#endif
typedef struct thread_lhf
{
	int writedatalen;
	unsigned char *writedata;
	int server_read_ssl;
	int server_write_ssl;
	int client_read_ssl;
	int client_write_ssl;

}thread_lhf;
#define    MSGKEY   1000  
  
struct msgStru  
{  
    long    msgType;  
    char    msgText[8184];  
};  


pthread_mutex_t mutex1,mutex2;



int client_writedatalen=0;
unsigned char *client_writedata=NULL;
int server_writedatalen=0;
unsigned char *server_writedata=NULL;



int fd_socket=0;


#ifndef OPENSSL_NO_RSA
static RSA MS_CALLBACK *tmp_rsa_cb(SSL *s, int is_export, int keylength);
#endif
static int sv_body(char *hostname, int s, unsigned char *context);
static int init_ssl_connection(SSL *s);
static void print_stats(BIO *bp,SSL_CTX *ctx);
static int generate_session_id(const SSL *ssl, unsigned char *id,
				unsigned int *id_len);
#ifndef OPENSSL_NO_DH
static DH *load_dh_param(const char *dhfile);
static DH *get_dh512(void);
#endif

void  *thread_main(void *params);

#ifndef OPENSSL_NO_DH
static unsigned char dh512_p[]={
	0xDA,0x58,0x3C,0x16,0xD9,0x85,0x22,0x89,0xD0,0xE4,0xAF,0x75,
	0x6F,0x4C,0xCA,0x92,0xDD,0x4B,0xE5,0x33,0xB8,0x04,0xFB,0x0F,
	0xED,0x94,0xEF,0x9C,0x8A,0x44,0x03,0xED,0x57,0x46,0x50,0xD3,
	0x69,0x99,0xDB,0x29,0xD7,0x76,0x27,0x6B,0xA2,0xD3,0xD4,0x12,
	0xE2,0x18,0xF4,0xDD,0x1E,0x08,0x4C,0xF6,0xD8,0x00,0x3E,0x7C,
	0x47,0x74,0xE8,0x33,
	};
static unsigned char dh512_g[]={
	0x02,
	};

static DH *get_dh512(void)
	{
	DH *dh=NULL;

	if ((dh=DH_new()) == NULL) return(NULL);
	dh->p=BN_bin2bn(dh512_p,sizeof(dh512_p),NULL);
	dh->g=BN_bin2bn(dh512_g,sizeof(dh512_g),NULL);
	if ((dh->p == NULL) || (dh->g == NULL))
		return(NULL);
	return(dh);
	}
#endif


#ifndef OPENSSL_NO_RSA
static RSA MS_CALLBACK *tmp_rsa_cb(SSL *s, int is_export, int keylength)
	{
	BIGNUM *bn = NULL;
	static RSA *rsa_tmp=NULL;

	if (!rsa_tmp && ((bn = BN_new()) == NULL))
		BIO_printf(bio_err,"Allocation error in generating RSA key\n");
	if (!rsa_tmp && bn)
		{
		if (!s_quiet)
			{
			BIO_printf(bio_err,"Generating temp (%d bit) RSA key...",keylength);
			(void)BIO_flush(bio_err);
			}
		if(!BN_set_word(bn, RSA_F4) || ((rsa_tmp = RSA_new()) == NULL) ||
				!RSA_generate_key_ex(rsa_tmp, keylength, bn, NULL))
			{
			if(rsa_tmp) RSA_free(rsa_tmp);
			rsa_tmp = NULL;
			}
		if (!s_quiet)
			{
			BIO_printf(bio_err,"\n");
			(void)BIO_flush(bio_err);
			}
		BN_free(bn);
		}
	return(rsa_tmp);
	}
#endif

int main(int, char **);
int main(int argc, char *argv[])
{
	short port=PORT_LHF;
	char *CApath=NULL,*CAfile=TestCAfile;
	unsigned char *context = NULL;
	int ret=1;
	int off=0;
	int no_tmp_rsa=0,no_dhe=0,no_ecdhe=0,nocert=0;
	int state=0;
	const SSL_METHOD *meth=NULL;
	int socket_type=SOCK_STREAM;
	ENGINE *e=NULL;
	char *inrand=NULL;
	int s_cert_format = FORMAT_PEM, s_key_format = FORMAT_PEM;
	char *passarg = NULL, *pass = "neldtv";
	char *dpassarg = NULL, *dpass = NULL;
	int s_dcert_format = FORMAT_PEM, s_dkey_format = FORMAT_PEM;
	X509 *s_cert = NULL, *s_dcert = NULL;
	EVP_PKEY *s_key = NULL, *s_dkey = NULL;
	int no_cache = 0;
	pthread_mutex_init(&mutex1,NULL,NULL);
	pthread_mutex_init(&mutex2,NULL,NULL);
	pthread_mutex_lock(&mutex1);
	pthread_mutex_lock(&mutex2);
   


	//meth=SSLv2_server_method();
  meth=TLSv1_server_method();
	
	if (bio_err == NULL)
		bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	verify_depth=0;
	

	
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();

	bio_s_out=BIO_new_fp(stdout,BIO_NOCLOSE);
		
	printf("lhf:SSL_CTX_new start\n");
	ctx=SSL_CTX_new(meth);
	if (ctx == NULL)
		{
		ERR_print_errors(bio_err);
		goto end;
		}
	SSL_CTX_set_quiet_shutdown(ctx,1);
	SSL_CTX_set_options(ctx,off);//lhf:ssl_lib.c:SSL_CTX_ctrl:cmd=32
	

	SSL_CTX_sess_set_cache_size(ctx,128); 

		DH *dh=NULL;
		BIO_printf(bio_s_out,"Using default temp DH parameters\n");
		dh=get_dh512();
		(void)BIO_flush(bio_s_out);
		SSL_CTX_set_tmp_dh(ctx,dh);//lhf:ssl_lib.c:SSL_CTX_ctrl:cmd=3

#ifndef OPENSSL_NO_ECDH
	if (!no_ecdhe)
		{
		EC_KEY *ecdh=NULL;

		BIO_printf(bio_s_out,"Using default temp ECDH parameters\n");
		ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
		(void)BIO_flush(bio_s_out);
		SSL_CTX_set_tmp_ecdh(ctx,ecdh);
		EC_KEY_free(ecdh);
		}
#endif

	

	SSL_CTX_set_tmp_rsa_callback(ctx,tmp_rsa_cb);

	SSL_CTX_set_verify(ctx,s_server_verify,verify_callback);

	SSL_CTX_set_default_passwd_cb_userdata(ctx,(void *)pass);
	
	if (SSL_CTX_use_certificate_chain_file(ctx, certchain) <= 0) 
	{
		ERR_print_errors_fp(stderr);
		SSL_CTX_free (ctx);
		return 0;
	}
			
	if (SSL_CTX_use_PrivateKey_file(ctx, certchainkey, SSL_FILETYPE_PEM) <= 0) 
	{
		ERR_print_errors_fp(stderr);
		SSL_CTX_free (ctx);
		return 0;
	
	}
	if (cipher != NULL) {
			if (!SSL_CTX_set_cipher_list(ctx, cipher)) {
				BIO_printf(bio_err, "error setting cipher list\n");
				ERR_print_errors(bio_err);
				goto end;
			}
		}
	
	SSL_CTX_set_session_id_context(ctx,(void*)&s_server_session_id_context,
		sizeof s_server_session_id_context);

	/* Set DTLS cookie generation and verification callbacks */
	SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie_callback);
	SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie_callback);
	
	BIO_printf(bio_s_out,"ACCEPT\n");
	(void)BIO_flush(bio_s_out);
	printf("lhf:s_server.c:do_server start\n");
	do_server(port,socket_type,&accept_socket,sv_body, context);
	print_stats(bio_s_out,ctx);
	ret=0;
	printf("lhf:s_server.c:do_server end\n");
	if(accept_socket>=0)
		close(accept_socket);
	
end:
	if (ctx != NULL) SSL_CTX_free(ctx);
	if (s_cert)
		X509_free(s_cert);
	if (s_dcert)
		X509_free(s_dcert);
	if (s_key)
		EVP_PKEY_free(s_key);
	if (s_dkey)
		EVP_PKEY_free(s_dkey);
	if (pass)
		OPENSSL_free(pass);
	if (dpass)
		OPENSSL_free(dpass);
	if (bio_s_out != NULL)
		{
        BIO_free(bio_s_out);
		bio_s_out=NULL;
		}

	OPENSSL_EXIT(ret);
	
	
}


static void print_stats(BIO *bio, SSL_CTX *ssl_ctx)
	{
	BIO_printf(bio,"%4ld items in the session cache\n",
		SSL_CTX_sess_number(ssl_ctx));
	BIO_printf(bio,"%4ld client connects (SSL_connect())\n",
		SSL_CTX_sess_connect(ssl_ctx));
	BIO_printf(bio,"%4ld client renegotiates (SSL_connect())\n",
		SSL_CTX_sess_connect_renegotiate(ssl_ctx));
	BIO_printf(bio,"%4ld client connects that finished\n",
		SSL_CTX_sess_connect_good(ssl_ctx));
	BIO_printf(bio,"%4ld server accepts (SSL_accept())\n",
		SSL_CTX_sess_accept(ssl_ctx));
	BIO_printf(bio,"%4ld server renegotiates (SSL_accept())\n",
		SSL_CTX_sess_accept_renegotiate(ssl_ctx));
	BIO_printf(bio,"%4ld server accepts that finished\n",
		SSL_CTX_sess_accept_good(ssl_ctx));
	BIO_printf(bio,"%4ld session cache hits\n",SSL_CTX_sess_hits(ssl_ctx));
	BIO_printf(bio,"%4ld session cache misses\n",SSL_CTX_sess_misses(ssl_ctx));
	BIO_printf(bio,"%4ld session cache timeouts\n",SSL_CTX_sess_timeouts(ssl_ctx));
	BIO_printf(bio,"%4ld callback cache hits\n",SSL_CTX_sess_cb_hits(ssl_ctx));
	BIO_printf(bio,"%4ld cache full overflows (%ld allowed)\n",
		SSL_CTX_sess_cache_full(ssl_ctx),
		SSL_CTX_sess_get_cache_size(ssl_ctx));
	}

static int sv_body(char *hostname, int s, unsigned char *context)
{
	
	char *buf=NULL;
	fd_set readfds;
	fd_set writefds;
	int ret=1,width;
	int k,i;
	unsigned long l;
	SSL *con=NULL;
	BIO *sbio;
	thread_lhf params;
	pthread_t	pid;

	struct timeval timeout;
	struct timeval *timeoutp=NULL;

	memset(&params,0,sizeof(params));
	
    


	if ((buf=OPENSSL_malloc(bufsize)) == NULL)
		{
		BIO_printf(bio_err,"out of memory\n");
		goto err;
		}


	if (con == NULL) {
		con=SSL_new(ctx);
		if(context)
		      SSL_set_session_id_context(con, context,
						 strlen((char *)context));
	}
	SSL_clear(con);	
	sbio=BIO_new_socket(s,BIO_NOCLOSE);
	printf("lhf:s_server.c:BIO_new_socket end\n");
	SSL_set_bio(con,sbio,sbio);
	SSL_set_accept_state(con);
	/* SSL_set_fd(con,s); */
	//width=s+1;
	width=SSL_get_fd(con)+1;//==width=s+1
	int first=0;
	int loop=0;
	int read_from_terminal=0;
	int read_from_sslcon;
	for (;;)
		{
		//if(loop==10)break;
		//pthread_mutex_lock(&mutex);
		printf("-------lhf:98server:for=%d---------\n",++loop);
		//printf("readdata length:%d\n",readdatalen);
		//printf("readdata data:%s\n",readdata);
        
		
		read_from_sslcon = SSL_pending(con);

	 
	      if(read_from_terminal){
		  	//pthread_mutex_lock(&mutex);
			   FD_ZERO(&writefds);
			   openssl_fdset(s,&writefds);
			   
			   i=select(width,NULL,(void *)&writefds,NULL,timeoutp);
			   read_from_sslcon=1;
	         
			  //pthread_mutex_unlock(&mutex);
			 
	 
		   }

		
		if (!read_from_sslcon)
			{
			FD_ZERO(&readfds);
			openssl_fdset(s,&readfds);
			i=select(width,(void *)&readfds,NULL,NULL,timeoutp);
			if (FD_ISSET(s,&readfds))read_from_sslcon = 1;

			}
				

	    
			if (i <= 0) continue;
        if(server_writedata!=NULL && server_writedatalen!=0){
			 k=SSL_write(con,&(server_writedata[0]),(unsigned int)server_writedatalen);
			 printf("98server write length=%d\n",k);
			 
             switch (SSL_get_error(con,k))
			 	{
				case SSL_ERROR_NONE:
					printf("98server write ok\n");
					server_writedata=NULL;
					server_writedatalen=0;
					read_from_terminal=0;
					read_from_sslcon=0;
					params.server_write_ssl=1;
					break;
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_READ:
				case SSL_ERROR_WANT_X509_LOOKUP:
					BIO_printf(bio_s_out,"Write BLOCK\n");
					break;
				case SSL_ERROR_SYSCALL:
				case SSL_ERROR_SSL:
					BIO_printf(bio_s_out,"ERROR\n");
					ERR_print_errors(bio_err);
					ret=1;
					goto err;
					/* break; */
				case SSL_ERROR_ZERO_RETURN:
					BIO_printf(bio_s_out,"DONE\n");
					ret=1;
					goto err;
				}
			 
		}
	

	
		if (read_from_sslcon)
			{
			if (!SSL_is_init_finished(con))
				{
				printf("lhf:98server:init_ssl_connection start\n");
				i=init_ssl_connection(con);
				printf("lhf:98server:init_ssl_connection end ret=%d\n",i);
				
				if (i < 0)
					{
					ret=0;
					goto err;
					}
				else if (i == 0)
					{
					ret=1;
					goto err;
					}
				}
			else
				{
again:	       
				
				i=SSL_read(con,(char *)buf,bufsize);
				printf("98server read data from app\n");
				printf("read length:%d\n",i);
				printf("read data:%s\n",buf);
                int k=SSL_get_error(con,i);
				
				switch (k)
					{
				case SSL_ERROR_NONE:
					
					/*send data to account.xiaomi.com*/

					if(!params.server_write_ssl){
					params.writedatalen=i;
					params.writedata=buf;
					
					//readdata=lhfdata;
					//readdatalen=3195;
					read_from_terminal=1;
					
					pthread_create(&pid,NULL,&thread_main,(void *)(&params));
					printf("........98server waiting....,98client work.......\n");
					pthread_mutex_unlock(&mutex1);
					pthread_mutex_lock(&mutex2);
					
					//pthread_mutex_lock(&mutex);
					}
					else {
						
						if(i>0){
						client_writedata=buf;
						client_writedatalen=i;
						read_from_terminal=1;
						printf("........98server waiting....,98client work...\n");
						pthread_mutex_unlock(&mutex1);
					    pthread_mutex_lock(&mutex2);
						}
						
					}
						
					//pthread_detach(pid);
					
					//pthread_join(pid);

					/*--------*/
					if (SSL_pending(con)) goto again;
					break;
				case SSL_ERROR_WANT_WRITE:
				case SSL_ERROR_WANT_READ:
					BIO_printf(bio_s_out,"Read BLOCK\n");
					break;
				case SSL_ERROR_SYSCALL:
				case SSL_ERROR_SSL:
					BIO_printf(bio_s_out,"ERROR\n");
					ERR_print_errors(bio_err);
					ret=1;
					goto err;
				case SSL_ERROR_ZERO_RETURN:
					BIO_printf(bio_s_out,"DONE\n");
					ret=1;
					goto err;
					}
				}
			}
		printf("--------lhf:98server:end for=%d----------\n",loop);
		//pthread_mutex_unlock(&mutex);
		}
err:
	if (con != NULL)
		{
		BIO_printf(bio_s_out,"shutting down SSL\n");
#if 1
		SSL_set_shutdown(con,SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
#else
		SSL_shutdown(con);
#endif
		SSL_free(con);
		}
	BIO_printf(bio_s_out,"CONNECTION CLOSED\n");
	if (buf != NULL)
		{
		OPENSSL_cleanse(buf,bufsize);
		OPENSSL_free(buf);
		}
	if (ret >= 0)
		BIO_printf(bio_s_out,"ACCEPT\n");
	return(ret);
	 pthread_mutex_unlock(&mutex2);
	
}
void  *thread_main(void *params)
 {
    pthread_mutex_lock(&mutex1);
	
	SSL *con=NULL;
	short port=443;
	char *host=XIAOMIACCOUNT;;
	X509 *cert = NULL;
	
	char *cert_file=NULL,*key_file=NULL,*pass=NULL;
	char *CAfile=TestCAfile;
	char *CApath=NULL;
	int s,k,width,state=0;
	const SSL_METHOD *meth=NULL;
	int socket_type=SOCK_STREAM;
	BIO *sbio;
	int cert_format = FORMAT_PEM, key_format = FORMAT_PEM;
	unsigned int off=0;
	int write_tty,read_tty,write_ssl,read_ssl,tty_on,ssl_pending;
	SSL_CTX *ctx=NULL;
	int loop=0;
	BIO *bio_c_out=NULL;

	fd_set readfds,writefds;
	int full_log=1;
	int cbuf_len,cbuf_off;
	int sbuf_len,sbuf_off;
	char *cbuf=NULL,*sbuf=NULL,*mbuf=NULL;
	int reconnect=0,badop=0,verify=SSL_VERIFY_NONE,bugs=0;
	int ret=1,in_init=1,i,nbio_test=0;
	X509_VERIFY_PARAM *vpm = NULL;
	struct timeval timeout, *timeoutp;
	pthread_mutex_t mutex;
	pthread_mutex_init (&mutex,NULL);


	printf(".........s_client start...........\n");

    

	thread_lhf *param = (thread_lhf *)params;
	if (	((cbuf=OPENSSL_malloc(BUFSIZZ)) == NULL) ||
		((sbuf=OPENSSL_malloc(BUFSIZZ)) == NULL) ||
		((mbuf=OPENSSL_malloc(BUFSIZZ)) == NULL))
		{
		BIO_printf(bio_err,"out of memory\n");
		goto end;
		}

	meth=TLSv1_client_method();

		
	if (bio_err == NULL)
		bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	if (bio_c_out == NULL)
		bio_c_out=BIO_new_fp(stdout,BIO_NOCLOSE);
			

	/*SSL_CTX new */
	ctx=SSL_CTX_new(meth);

	
	SSL_CTX_set_options(ctx,off);

	SSL_CTX_set_verify(ctx,verify,verify_callback);
	
	if (!SSL_CTX_set_default_verify_paths(ctx))
		{
			goto end; 
		}
		con=SSL_new(ctx);
re_start:
	   
		if (init_client(&s,host,port,socket_type) == 0)
		{
			printf("connect:errno=%d\n",get_last_socket_error());
			close(s);
			goto end;
		}
		printf("CONNECTED(%08X)\n",s);
		sbio=BIO_new_socket(s,BIO_NOCLOSE);
		SSL_set_bio(con,sbio,sbio);
		
		SSL_set_connect_state(con);
	width=SSL_get_fd(con)+1;//==s+1
	//width=s+1;
    

	read_tty=1;
	write_tty=0;
	tty_on=0;
	read_ssl=0;
	write_ssl=1;
	cbuf_len=0;
	cbuf_off=0;
	sbuf_len=0;
	sbuf_off=0;
	int client_read_ssl=0;
	int client_write_ssl=1;

	
	/*-------------------generate EVP key---------------*/
	for (;;)
		{
		
		
		printf("-------lhf:98client:for=%d---------\n",++loop);
		
			FD_ZERO(&readfds);
			FD_ZERO(&writefds);
			timeoutp=NULL;
			if (SSL_in_init(con) && !SSL_total_renegotiations(con))
				{
				}
			else
				{
					
				}
			ssl_pending = read_ssl && SSL_pending(con);
			
			if (!ssl_pending)
				{
				
					if (client_read_ssl){
						openssl_fdset(SSL_get_fd(con),&readfds);
					    i=select(width,(void *)&readfds,NULL,NULL,timeoutp);
						
						}
					else if (client_write_ssl){
						openssl_fdset(SSL_get_fd(con),&writefds);
					    i=select(width,NULL,(void *)&writefds,NULL,timeoutp);
						
						}

	

				}
		    if(i<0)continue;
			
		   if(FD_ISSET(SSL_get_fd(con),&writefds) &&param->writedatalen!=0 && param->writedata!=NULL){
		   		cbuf_len=param->writedatalen;
				
                k=SSL_write(con,&(param->writedata[cbuf_off]),(unsigned int)param->writedatalen);
				
				switch (SSL_get_error(con,k))
				{
					case SSL_ERROR_NONE:		
					   cbuf_off+=k;
					   cbuf_len-=k;
					   param->writedatalen=0;
					   param->writedata=NULL;
					   printf("98client ssl_write ok\n");
						if (k <= 0) goto end;
								/* we have done a  write(con,NULL,0); */
						if (cbuf_len <= 0)
							{
								read_tty=1;
								write_ssl=0;
								client_read_ssl=1;
								client_write_ssl=0;
							}
						else /* if (cbuf_len > 0) */
							{
								read_tty=0;
								write_ssl=1;
								}
							break;
						case SSL_ERROR_SYSCALL:
							if ((k != 0) || (cbuf_len != 0))
								{
									BIO_printf(bio_err,"write:errno=%d\n",
										get_last_socket_error());
										goto shut;
								}
								else
									{
										read_tty=1;
										write_ssl=0;
								}
								break;

		
						}

		   }
		   else if(FD_ISSET(SSL_get_fd(con),&writefds)&& client_writedata!=NULL && client_writedatalen!=0){
              
          
			   k=SSL_write(con,&(client_writedata[0]),client_writedatalen);
			   //printf("client write length:%d\n",k);
			   //printf("client write data:%s\n",client_writedata);
			   switch (SSL_get_error(con,k)){
                 case SSL_ERROR_NONE:		
					   cbuf_off+=k;
					   cbuf_len-=k;
					   client_writedatalen=0;
					   client_writedata=NULL;
						if (k <= 0) goto end;
								/* we have done a  write(con,NULL,0); */
								client_read_ssl=1;
								client_write_ssl=0;
							printf("98client ssl_write ok\n");
							break;
						case SSL_ERROR_SYSCALL:
							if ((k != 0) || (cbuf_len != 0))
								{
									BIO_printf(bio_err,"write:errno=%d\n",
										get_last_socket_error());
										goto shut;
								}
								else
									{
										read_tty=1;
										write_ssl=0;
								}
								break;

			   }

			   

		   }
		  
   else if (ssl_pending || FD_ISSET(SSL_get_fd(con),&readfds))
     {
lhfagain:
					printf(" 98client read data from xiaomiserver\n");
					k=SSL_read(con,sbuf, BUFSIZZ);
					printf(" receive length:%d\n",k);
					printf(" receive data:%s\n",sbuf);
					
					switch (SSL_get_error(con,k))
						{
							case SSL_ERROR_NONE:
								if (k <= 0)goto end;
								sbuf_off=0;
								sbuf_len=k;
                                
								//read_ssl=0;
							
								read_ssl=1;
								client_write_ssl=1;
								client_read_ssl=0;
								if (SSL_pending(con))
									goto lhfagain;
								
								server_writedata=sbuf;
								server_writedatalen=k;
								printf(".....98client waiting......,98server work...\n");
                                pthread_mutex_unlock(&mutex2);
								pthread_mutex_lock(&mutex1);
					
								break;
							case SSL_ERROR_SYSCALL:
								ret=get_last_socket_error();
								BIO_printf(bio_err,"read:errno=%d\n",ret);
								goto shut;
							case SSL_ERROR_SSL:
								ERR_print_errors(bio_err);
								goto shut;
						}
					
				

   }
		   
			
			printf("--------lhf:98client:end for=%d----------\n",loop);	
			
		}
		ret=0;
shut:
	SSL_shutdown(con);
	close(SSL_get_fd(con));
end:
	if (con != NULL)
		{
			SSL_free(con);
		
		}
	if (ctx != NULL) SSL_CTX_free(ctx);
	if (cert)
		X509_free(cert);
	if (pass)
		OPENSSL_free(pass);
	if (vpm)
		X509_VERIFY_PARAM_free(vpm);
	if (cbuf != NULL) { OPENSSL_cleanse(cbuf,BUFSIZZ); OPENSSL_free(cbuf); }
	if (sbuf != NULL) { OPENSSL_cleanse(sbuf,BUFSIZZ); OPENSSL_free(sbuf); }
	
	if (bio_c_out != NULL)
		{
			BIO_free(bio_c_out);
			bio_c_out=NULL;
		}
  pthread_mutex_unlock(&mutex1);
}



static int init_ssl_connection(SSL *con)
{
	
	int i;
	const char *str;
	X509 *peer;
	long verify_error;
	MS_STATIC char buf[BUFSIZ];

	i=SSL_accept(con);
	printf("lhf:98server:SSL_accept return=%d\n",i);
	if (i <= 0)
		{
		if (BIO_sock_should_retry(i))
			{
			BIO_printf(bio_s_out,"DELAY\n");
			return(1);
			}

		BIO_printf(bio_err,"ERROR\n");
		verify_error=SSL_get_verify_result(con);
		if (verify_error != X509_V_OK)
			{
			BIO_printf(bio_err,"verify error:%s\n",
				X509_verify_cert_error_string(verify_error));
			}
		else
			ERR_print_errors(bio_err);
		return(0);
		}

	PEM_write_bio_SSL_SESSION(bio_s_out,SSL_get_session(con));

	peer=SSL_get_peer_certificate(con);
	if (peer != NULL)
		{
		BIO_printf(bio_s_out,"Client certificate\n");
		PEM_write_bio_X509(bio_s_out,peer);
		X509_NAME_oneline(X509_get_subject_name(peer),buf,sizeof buf);
		BIO_printf(bio_s_out,"subject=%s\n",buf);
		X509_NAME_oneline(X509_get_issuer_name(peer),buf,sizeof buf);
		BIO_printf(bio_s_out,"issuer=%s\n",buf);
		X509_free(peer);
		}

	if (SSL_get_shared_ciphers(con,buf,sizeof buf) != NULL)
		BIO_printf(bio_s_out,"Shared ciphers:%s\n",buf);
	str=SSL_CIPHER_get_name(SSL_get_current_cipher(con));
	BIO_printf(bio_s_out,"CIPHER is %s\n",(str != NULL)?str:"(NONE)");


	BIO_printf(bio_s_out, "Secure Renegotiation IS%s supported\n",
		      SSL_get_secure_renegotiation_support(con) ? "" : " NOT");
	return(1);
	
	
}

