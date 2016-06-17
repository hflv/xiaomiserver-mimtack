#include <stdio.h>  
#include <sys/types.h>  
#include <sys/ipc.h>  
#include <sys/msg.h>  
#include <errno.h>  
  
#define    MSGKEY   1000  
  
struct msgStru  
{  
    long    msgType; 
	
    char    msgText[4096];  
};  
  
void main()  
{  
   int   iMsgId;  
   struct msgStru slQMsg,slRcvMsg;  
   int   ilRc;  
  char input[1024];
   iMsgId = msgget(MSGKEY,IPC_EXCL);/*检查消息队列是否存在*/  
   if ( iMsgId < 0 ){  
       iMsgId = msgget(MSGKEY,IPC_CREAT|0666);/*创建消息队列*/  
       if ( iMsgId < 0 ){  
           printf("create msgQ error! errno=%d[%s]\n",errno,strerror(errno));  
           exit(-1);  
       }  
   }  
  
   slQMsg.msgType = 100; 
   
   
   while(1){
   	scanf("%s",input);
	strcpy(slQMsg.msgText,input);
	//slQMsg.msgTextlen=5;
   ilRc = msgsnd(iMsgId, &slQMsg, sizeof(struct msgStru),IPC_NOWAIT);  
   if( ilRc < 0 ) {  
       printf("msgsnd()写消息队列失败,errno=%d[%s]\n",errno,strerror(errno));  
       exit(-1);  
   }  
     
   ilRc = msgrcv(iMsgId,&slRcvMsg,sizeof(struct msgStru),0,0);/*接收消息队列*/  
   printf("text=[%s]\n",slRcvMsg.msgText);  
   	}
   

  
   msgctl(iMsgId,IPC_RMID,0);  /* 删除消息队列 */  
   exit(0);  
}

