#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "sha512.h"

#include "base64.h"

#define F "sign.txt"
#define TMEP_FILE 	"dianjing_certificate"
#define   LOGD			printf

#define  BUF_MAX_SIZE	(1024)
#define  USING_TEST_MODE	0

/**
 * Copyright (C), 2017-2018, DianJing Tech. Co., Ltd.
 * Author: wangkang
 * Description:     加解密测试程序的实现
 * Version:   
 * Function List: 
 * History: 
 * TEL : QQ450718196,phone:17665264299
 */
//将其重定向到文件中去
void filePrint(char *out,FILE *fp)
{
    char *p;
    for (p = out; p < out+64; p += 8) {
        // 8 byte is 64 bit
        printf("%lx", *(uint64_t*)p);
		fprintf(fp,"%lx",*(uint64_t*)p);
    }
	
	printf("\r\n");
}

void DebugPrint(char *out)
{
    char *p;
    for (p = out; p < out+64; p += 8) {
        // 8 byte is 64 bit
        printf("%lx", *(uint64_t*)p);
    }
	
	printf("\r\n");
}

int  calculation_certificate(char *mac,char *product,char *company,char *outSign)
{
	char base64_input[BUF_MAX_SIZE];
	char base64_output[BUF_MAX_SIZE];
	int ret  = 1;
	char  * tmp = base64_input;
	
	memset(base64_input,0,BUF_MAX_SIZE);
	memset(base64_input,0,BUF_MAX_SIZE);
	memset(base64_output,0,sizeof(base64_output));
	sprintf(tmp,"DianJingTech:Mac:%s Product:%s Company:%s",mac,product,company);
	int len = strlen(tmp);
	
	do
	{
		//base64 encode
		if( base64_encode(tmp, len - 1, base64_output) != 0)
		{
			LOGD(" base64_encode len=%d error !!\r\n",len);
			break;
		}
		
		//base64 encode correct
		tmp = base64_output;
		//sha512 encode
		len = strlen(tmp);
		sha512_buffer(tmp,len , outSign);
		
		ret = 0;
	}while(0);
	
	return ret;	
}

int register_certificate(char *mac,char *product,char *company)
{
	FILE *fp = NULL;
	char tmp[BUF_MAX_SIZE];
	int nwrite = 0;
	int ret  = 1;
	memset(tmp,0,BUF_MAX_SIZE);	
	
	do
	{
		if(calculation_certificate(mac,product,company,tmp) != 0)
		{
			LOGD("calculation_certificate mac=%s product=%s company=%s error!!!\r\n",mac,product,company);
			break;
		}

	#if USING_TEST_MODE
		fp = fopen(TMEP_FILE,"w+");
		if(fp == NULL)
		{
			LOGD(" fopen %s error !!\r\n",TMEP_FILE);
			break;
		}
		filePrint(tmp,fp);
		// goback to file start
		fseek(fp, 0, SEEK_SET);
		fflush(fp);
	#else
		DebugPrint(tmp);
	#endif	
		ret = 0;
	}while(0);
	
	if(fp)
		fclose(fp);
	fp = NULL;
	
	return ret;
}

/*
	比较签名证书是否正确
*/
int compare_certificate(const char *certificate,char *mac,char *product,char *company)
{
	char tmp[BUF_MAX_SIZE];
	int ret  = 0;
	memset(tmp,0,BUF_MAX_SIZE);
	
	do
	{
		if(calculation_certificate(mac,product,company,tmp) != 0)
		{
			ret = -1;
			LOGD("calculation_certificate mac=%s product=%s company=%s error!!!\r\n",mac,product,company);
			break;
		}
		
		ret = strcmp(certificate,tmp);
	}while(0);
	
	return ret;
}

int main(void)
{
	register_certificate("00:01:6C:06:A6:29","微商系统","深圳市点睛科技有限公司");
	return 0;
}