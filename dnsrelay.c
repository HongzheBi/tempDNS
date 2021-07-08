#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

/**************************************** Header ****************************************/
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <windows.h> 
#include <sys/types.h>
#include <string.h>
#include <WS2tcpip.h>
#include <time.h>
#pragma comment(lib,"wsock32.lib")
#pragma comment(lib,"ws2_32.lib")

/**************************************** Macro ****************************************/
#define BUF_SIZE 1024
#define SRV_PORT 53
#define TTL_TIME 5000    //超时时间2s
#define CACHE_NUMBER 10 //cache长度
typedef unsigned short U16;

/**************************************** Struct ****************************************/
typedef struct DNS_HDR {	//DNS报文头部
	U16 ID;			//头部ID，2字节
	U16 Flags;		//Flags
	U16 QDCOUNT;	//question计数
	U16 ANCOUNT;	//answer计数
	U16 NSCOUNT;	//authority计数
	U16 ARCOUNT;	//additional计数
}DNS_HDR;

typedef struct DNS_QUE {	//DNS的Queries部分(查询问题部分)
	U16 type;		//查询类型
	U16 classes;	//查询类
}DNS_QUE;

typedef struct ConId {	//对中继转发的报文进行ID转换
	struct sockaddr_in addr;//保存Client地址
	char clientID[2];		//Client发给本机的ID（允许重复）
	char convertID[2];		//本机中继转发的ID（不允许重复）
	clock_t starttime;      //转发出去的时间，2秒后超时自动清除该链结
	int LRU_cache;          //指向LRU中的偏移量
	struct ConId* nextptr;
}ConId;

typedef struct LRU_Cache {//缓存中继出去的报文,只记录类型是A的，ipv4
	char url[200];
	char ip[20];
	clock_t starttime;
	int flag;             //初始为0，意味着不能替换，当超时或ip已经被写入，则可以替换
	int lru;              //LRU参数
	int flag_success;     //可以使用
}LRU_Cache;

/*
struct sockaddr_in {
	short int sin_family;		//通信类型
	unsigned short int sin_port;//端口
	struct in_addr sin_addr;	//Internet地址
	unsigned char sin_zero[8];	//与sockaddr结构的长度相同
};

struct in_addr {	//Internet 地址
	unsigned long s_addr;
};
*/

/**************************************** Global ****************************************/
char srv_ip[] = "223.5.5.5"; //AliDNS_server
char host_file[] = "dnsrelay.txt";
int flag_whether_cache = 0;
char local_url[1000][200] = {0};
char local_ip[1000][20] = {0};
int local_number = 0;

WSADATA wsaData;
SOCKET local_sock, outside_sock;
struct sockaddr_in local_addr, outside_addr;
struct sockaddr_in temp;	//for monitor
struct sockaddr_in client,test;
int len_addr;

int dbg_flag = 0;	//use to flag the Debug information output. 
					//0:no output 1:simple output 2:complex output

ConId* headptr,* tailptr;	//id转换链表

LRU_Cache cache[CACHE_NUMBER];      //缓存区


/**************************************** Function ****************************************/

//打印网络类型的ip
void print_inetIp(char ip[]) {
	int i;
	for (i = 0; i < 3; i++) {
		printf("%u", (unsigned char)ip[i]);
		printf(".");
	}
	printf("%u\n", (unsigned char)ip[i]);
}

//添加url至缓存，lru算法，成功添加返回偏移量，不成功返回-1
int add_Cache_URL(char url[100]) {
	int max_cache;             //LRU最大项
	int max_LRU;
	int i;
	clock_t nowtime = clock();
	max_cache = 0;
	max_LRU = cache[0].lru;
	//判断重复，有重复不添加
	for (i = 0; i < CACHE_NUMBER; i++) {
		if (strcmp(cache[i].url, url) == 0) {
			return -2;
		}
	}
	//尝试找到最大可替换lru
	for (i = 0; i < CACHE_NUMBER; i++) {
		if (nowtime - cache[i].starttime > TTL_TIME) {//若超时可以替换
			cache[i].flag = 1;
		}
		if (cache[i].flag == 1) {
			if (cache[i].lru > cache[max_cache].lru) {
				max_cache = i;
			}
		}
	}
	
	if (cache[max_cache].flag) {//找到可替换项
		//替换
		
		cache[max_cache].flag = 0;
		cache[max_cache].starttime = clock();
		cache[max_cache].lru = 0;
		cache[max_cache].flag_success = 0;
		strcpy(cache[max_cache].url, url);
		
		//其他所有项目lru自加
		for (i = 0; i < CACHE_NUMBER; i++) {
			if (i != max_cache) {
				cache[i].lru++;
			}
		}
		return max_cache;
	}

	//未找到替换项目
	else {
		printf("未找到可替换项\n");
		return -1;
	}

}

//添加ip至下标为lru_cache的缓存区
void add_Cache_IP(char *ip, int lru_cache) {
	memcpy(cache[lru_cache].ip, ip, sizeof(ip));
	cache[lru_cache].flag_success = 1;
	cache[lru_cache].flag = 1;
	printf("\n调试缓冲区，获取ip后\n");
	for (int i = 0; i < CACHE_NUMBER; i++) {
		if (cache[i].flag_success == 1) {
			printf("%s ", cache[i].url);
			print_inetIp(cache[i].ip);
		}
	}
}

//从buf中获取IPv4
//成功：返回1
//不成功：返回0
int get_IP_From_Buf(char* buf, int length, char *ip) {
	int answer_number = (unsigned)(buf[6]) * 16 + (unsigned)buf[7];
	int offset = sizeof(DNS_HDR);
	
	char url_number[1024];
	char url[100];//用于跳过name
	memcpy(url_number, &(buf[sizeof(DNS_HDR)]), length);//跳过url头，下面保存的是请求报文
	int i = 0, j = 0, k = 0;
	while (url_number[i] != 0) {
		if (url_number[i] > 0 && url_number[i] <= 63) //如果是个计数
		{
			for (j = url_number[i], i++; j > 0; j--, i++, k++) //j是计数是几，k是目标位置下标，i是报文里的下标
				url[k] = url_number[i];
		}

		if (url_number[i] != 0)    //如果没结束就在dest里加个'.'
		{
			url[k] = '.';
			k++;
		}
	}
	url[k] = '\0';
	
	
	i++;
	i += 4;
	//此时i中保存answer字段第一项
	
	offset += i;
	//此时offset中保存answer字段第一项

	

	for (int p = 0; p < answer_number; p++) {
		
		memcpy(url_number, &(buf[offset]), length);//跳过url头以及Queries部分
		//跳过name
		i = 1;
		
		
		if (url_number[i + 1] == 0x00 && url_number[i + 2] == 0x01) {//如果此answer类型是A
			
			
			memcpy(ip, &(buf[offset + i + 11]), 4);//截取
			
			
			return 1;
		}
		else {//不是A
			int add_length = (16 * (unsigned)url_number[i + 9]) + (unsigned)url_number[i + 10];
			offset += 12;
			offset += add_length;
		}
	}
	return 0;
}

//在cache中匹配URL
int Cache_find(char *url, char **ip, int type) {
	if(type!=1){
		return 0;
	}
	for (int i = 0; i < CACHE_NUMBER; i++) {
		if (strcmp(url, cache[i].url) == 0 && cache[i].flag_success == 1) {
			*ip = cache[i].ip;
			if (dbg_flag) {
				printf("域名%s在Cache缓存中找到了！对应的ip为", url);
				print_inetIp(cache[i].ip);
			}
			return 1;
		}
	}
	if (dbg_flag) {
		printf("域名%s在Cache缓存中未找到\n", url);
	}
	return 0;
}

//清除超时ID转换链表
void delete_TTL_ConID() {
	ConId* ptr;
	ConId* deleteptr;
	ConId* lastptr;
	lastptr = headptr;
	ptr = headptr->nextptr;
	clock_t nowtime = clock();
	while (ptr) {
		if (nowtime - ptr->starttime > TTL_TIME) {
			//需要删除该链表
			deleteptr = ptr;
			if (ptr == tailptr) {//删除的是尾链
				lastptr->nextptr = NULL;
				tailptr = lastptr;
				free(deleteptr);
				break;
			}
			else {
				lastptr->nextptr = ptr->nextptr;
				ptr = ptr->nextptr;
				free(deleteptr);
				//lastptr = lastptr->nextptr;
			}
		}
		else {
			ptr = ptr->nextptr;
			lastptr = lastptr->nextptr;
		}
	}
	if (dbg_flag) {
		printf("已删除超时ID转换链结\n");
	}
}

//从报文中截取URL字段 查询类型
int get_url(char* buf, char* url,int length) {
	char url_number[100];
	memcpy(url_number, &(buf[sizeof(DNS_HDR)]), length);//跳过url头，下面保存的是
	int i = 0, j = 0, k = 0;

	//报文中的name很有趣，他的方式是www.bupt.edu.cn转二进制后是03 www 04 bupt 03 edu 02 cn
	while( url_number[i]!=0 ) {
		if (url_number[i] > 0 && url_number[i] <= 63) //如果是个计数
		{
			for (j = url_number[i], i++; j > 0; j--, i++, k++) //j是计数是几，k是目标位置下标，i是报文里的下标
				url[k] = url_number[i];
		}

		if (url_number[i] != 0)    //如果没结束就在dest里加个'.'
		{
			url[k] = '.';
			k++;
		}
	}
	url[k] = '\0';

	//判断请求类型type
	if (url_number[i + 1] == 0x00 && url_number[i + 2] == 0x01) {	//type字段0x01代表A类型 请求ipv4地址
		return 1;
	}
	if (url_number[i + 1] == 0x00 && url_number[i + 2] == 0x1c) {	//type字段0x01代表AAAA类型 请求ipv6地址
		return 2;
	}
	return 0;
}

//初始化：本地dns存储文件、ID转换链表、缓存表
void local_Init() {

	//初始化本地dns存储文件
	FILE* fp;
	if ((fp = fopen(host_file, "r")) == NULL) {
		printf("host error.\n");
		exit(-1);
	}
	int i = 0;
	while (!feof(fp)) {
		fscanf(fp, "%s %s", local_ip[i], local_url[i]);
		i++;
	}
	local_number = i;
	if (dbg_flag) {
		printf("本地存储的DNS有：\n");
		for (i = 0; i < local_number; i++) {
			printf("%s %s\n", local_ip[i], local_url[i]);
		}
	}

	//初始化ID转换链表
	headptr = (ConId*)malloc(sizeof(ConId));
	headptr->nextptr = NULL;
	tailptr = headptr;

	if (flag_whether_cache) {
		//初始化缓存表，每个项目都可以被替换
		for (i = 0; i < CACHE_NUMBER; i++) {
			cache[i].flag = 1;
			cache[i].lru = 0;
			cache[i].flag_success = 0;
		}
	}
	
}

//在本地DNS文件中匹配URL
int local_find(char *url,char **ip) {
	for (int i = 0; i < local_number; i++) {
		if (strcmp(url, local_url[i]) == 0) {
			*ip = local_ip[i];
			if (dbg_flag) {
				printf("域名%s在本地内存中找到了！对应的ip为%s\n", url, *ip);
			}

			return 1;
		}
	}
	return 0;
}

//处理查询报
void deal_Question(char buf[], int length, struct sockaddr_in temp) {
	char url[100];
	int i = 0, type = 0;
	unsigned char tage;

	//在报文中截取URL字段以及查询类型type
	type = get_url(buf, url, length);
	if (dbg_flag) {
		printf("\n...请求URL:%s\n", url);
		if (type == 1) {
			printf("\n...请求类型type:A\n\n");
		}
		else if(type == 2) {
			printf("\n...请求类型type:AAAA\n\n");
		}
	}

	//在本地文件中匹配对应URL
	char *ip;
	int flag = local_find(url, &ip);//flag标识是否在本地匹配成功（1：成功 2：失败）

	//成功：本地存储中查询到对应IP，并且该ip被屏蔽
	//或者：本地存储中查询到对应IP，该ip未被屏蔽，且请求类型是ipv4
	if ((flag == 1 && strcmp(ip, "0.0.0.0") == 0) || (flag == 1 && strcmp(ip, "0.0.0.0") != 0 && type==1)) {
		if (dbg_flag) {
			printf("开始本地DNS服务\n");
		}
		char send_buf[BUF_SIZE];//构建一个response报文
		unsigned short flag = htons(0x8180);//flag
		memcpy(&send_buf, buf, length);
		memcpy(&send_buf[2], &flag, sizeof(unsigned short));
		unsigned short answer = htons(0x0001);
		if (strcmp(ip, "0.0.0.0") == 0) {//屏蔽
			if (dbg_flag) {
				printf("屏蔽\n");
			}
			answer = htons(0x0000);
		}
		int offset = 0;
		memcpy(&send_buf[6], &answer, sizeof(unsigned short));
		char A_Answer[16];//A类型的response报文Answer报文是16个字节

		unsigned short Name = htons(0xc00c);//抓包得到的域名指针
		memcpy(&A_Answer, &Name, sizeof(Name));

		unsigned short Type = htons(0x0001);
		offset += sizeof(unsigned short);
		memcpy(A_Answer + offset, &Type, sizeof(unsigned short));

		unsigned short Class = htons(0x0001);
		offset += sizeof(unsigned short);
		memcpy(A_Answer + offset, &Class, sizeof(unsigned short));

		unsigned long TTL = htonl(0x00015180);//24个小时
		offset += sizeof(unsigned short);
		memcpy(A_Answer + offset, &TTL, sizeof(unsigned long));

		unsigned short Data_length = htons(0x0004);
		offset += sizeof(unsigned long);
		memcpy(A_Answer + offset, &Data_length, sizeof(unsigned short));

		unsigned long Address = (unsigned long)inet_addr(ip);
		offset += sizeof(unsigned short);
		memcpy(A_Answer + offset, &Address, sizeof(unsigned long));

		offset += length;
		offset += sizeof(unsigned long);
		memcpy(send_buf + length, A_Answer, sizeof(A_Answer));
		length = sendto(local_sock, send_buf, offset, 0, (struct sockaddr *)&temp, sizeof(temp));

		//反馈
		if (length < 0) {
			printf("send error\n");
			return;
		}
		if (dbg_flag) {
			printf("本地DNS回复包构建并发送完毕\n");
		}
		if (dbg_flag == 2) {
			printf("  ");
			for (i = 0; i < length; i++) {
				tage = (unsigned char)send_buf[i];
				printf("%02x ", tage);
				if (!((i + 1) % 4)) {
					printf("  ");
				}
				if (!((i + 1) % 16)) {
					printf("\n  ");
				}
			}
		}

		char* p;
		p = send_buf + length - 4;
		if (dbg_flag) {
			printf("\n本地DNS解析地址为 %s -> %u.%u.%u.%u\n\n\n", url, (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
		}
	}

	else if (flag_whether_cache && Cache_find(url, &ip, type) && type==1) {
		if (dbg_flag) {
			printf("开始缓存区DNS服务\n");
		}
		char send_buf[BUF_SIZE];//构建一个response报文
		unsigned short flag = htons(0x8180);//flag
		memcpy(&send_buf, buf, length);
		memcpy(&send_buf[2], &flag, sizeof(unsigned short));
		unsigned short answer = htons(0x0001);
		
		int offset = 0;
		memcpy(&send_buf[6], &answer, sizeof(unsigned short));
		char A_Answer[16];//A类型的response报文Answer报文是16个字节

		unsigned short Name = htons(0xc00c);//抓包得到的域名指针
		memcpy(&A_Answer, &Name, sizeof(Name));

		unsigned short Type = htons(0x0001);
		offset += sizeof(unsigned short);
		memcpy(A_Answer + offset, &Type, sizeof(unsigned short));

		unsigned short Class = htons(0x0001);
		offset += sizeof(unsigned short);
		memcpy(A_Answer + offset, &Class, sizeof(unsigned short));

		unsigned long TTL = htonl(0x00015180);//24个小时
		offset += sizeof(unsigned short);
		memcpy(A_Answer + offset, &TTL, sizeof(unsigned long));

		unsigned short Data_length = htons(0x0004);
		offset += sizeof(unsigned long);
		memcpy(A_Answer + offset, &Data_length, sizeof(unsigned short));
		
		offset += sizeof(unsigned short);
		memcpy(A_Answer + offset, ip, sizeof(unsigned char));
		ip++;
		offset += sizeof(unsigned char);
		memcpy(A_Answer + offset, ip, sizeof(unsigned char));
		ip++;
		offset += sizeof(unsigned char);
		memcpy(A_Answer + offset, ip, sizeof(unsigned char));
		ip++;
		offset += sizeof(unsigned char);
		memcpy(A_Answer + offset, ip, sizeof(unsigned char));

		offset += length;
		offset += sizeof(unsigned char);
		memcpy(send_buf + length, A_Answer, sizeof(A_Answer));

		length = sendto(local_sock, send_buf, offset, 0, (struct sockaddr *)&temp, sizeof(temp));

		//反馈
		if (length < 0) {
			printf("send error\n");
			return;
		}
		if (dbg_flag) {
			printf("缓存区DNS回复包构建并发送完毕\n");
		}
		if (dbg_flag == 2) {
			printf("  ");
			for (i = 0; i < length; i++) {
				tage = (unsigned char)send_buf[i];
				printf("%02x ", tage);
				if (!((i + 1) % 4)) {
					printf("  ");
				}
				if (!((i + 1) % 16)) {
					printf("\n  ");
				}
			}
		}

		char* p;
		p = send_buf + length - 4;
		if (dbg_flag) {
			printf("\n缓存区DNS解析地址为 %s -> %u.%u.%u.%u\n\n\n", url, (unsigned char)*p, (unsigned char)*(p + 1), (unsigned char)*(p + 2), (unsigned char)*(p + 3));
		}
	}

	//失败：本地存储中未查询到对应
	//或者：查找到对应ip，且未屏蔽，请求类型是ipv6的
	else{
		//删除ID转换链表中的超时项
		delete_TTL_ConID();

		
		//若是ipv4，添加url至缓存cache
		//成功：返回偏移量，之后添加至ConID中
		//失败：返回-1，不添加，ConID中偏移量设为-1
		int cache_flag = -1;
		if (type == 1 && flag_whether_cache) {
			cache_flag = add_Cache_URL(url);
		}
		

		if (dbg_flag) {
			if (type == 1) {
				printf("本地未找到对应URL，请中继\n");
			}
			else if (type == 2) {
				printf("本地未找到IPv6地址，请中继\n");
			}
		}

		//ID转换：处理报文ID，进行ID转换
			//尾插 保存client地址到addr,保存clientID；
			//查询本地表中是否与已有convertID发生重复
			//重复：增加id偏移值；
			//不重复：修改buf中ID字段为convertID = clientid + id偏移;
		ConId* ptr;
		ConId* newptr;
		int find_flag = 1;
		
		newptr = (ConId*)malloc(sizeof(ConId));
		tailptr->nextptr = newptr;
		tailptr = newptr;

		newptr->addr = temp;
		newptr->starttime = clock();//转发时间

		if (flag_whether_cache) {//启动缓存
			//若已经缓存，则保存偏移量
			if (cache_flag >= 0 && type == 1) {
				newptr->LRU_cache = cache_flag;
				if (dbg_flag) {
					printf("成功：已将URL添加至LRU缓存区\n");
				}
			}
			//若未缓存，则保存偏移量-1
			else {
				newptr->LRU_cache = -1;
				if (dbg_flag) {
					if (cache_flag == -1) {
						if (type == 1) {
							printf("失败：未将URL添加至LRU缓存区\n");
						}
						else {
							printf("非ipv4：不保存至缓存区\n");
						}
					}
					else if (cache_flag == -2) {
						printf("重复：不添加至cache\n");
					}
				}
			}
		}
	 
		newptr->nextptr = NULL;

		newptr->clientID[0] = buf[0];
		newptr->clientID[1] = buf[1];

		i = -1;
		while (find_flag) {
			i++;
			find_flag = 0;
			ptr = headptr->nextptr;
			while (ptr) {
				if (ptr->convertID[0] == buf[0]+i && ptr->convertID[1] == buf[1]+i) {
					find_flag = 1;
					break;
				}
				ptr = ptr->nextptr;
			}
		}
		newptr->convertID[0] = buf[0] + i;
		newptr->convertID[1] = buf[1] + i;
		
		buf[0] += i;
		buf[1] += i;

		if (dbg_flag) {
			printf("转换后的ID为：%02x %02x\n", (unsigned char)buf[0], (unsigned char)buf[1]);
		}

		//转发报文到指定DNS服务器
		length = sendto(local_sock, buf, length, 0, (struct sockaddr *)&outside_addr, sizeof(outside_addr));

		


		//反馈
		if (length < 0) {
			printf("send to server error\n");
			return;
		}
		if (dbg_flag) {
			printf("中继查询包构建并发送完毕\n");
		}
		if (dbg_flag == 2) {
			printf("  ");
			for (i = 0; i < length; i++) {
				tage = (unsigned char)buf[i];
				printf("%02x ", tage);
				if (!((i + 1) % 4)) {
					printf("  ");
				}
				if (!((i + 1) % 16)) {
					printf("\n  ");
				}
			}
		}

		//保存temp到client以便回送响应报
		//client = temp;//ID转换实现后将不再需要
	}
}

//处理响应报
void deal_Respond(char buf[], int length) {
	int i = 0;

	//处理报文ID，进行ID转换
		//查询本地表中convertID进行匹配
		//一定匹配成功，将该报文buf的id修改为对应clientID;	地址变量client赋值为对应client地址;
		//从表中删除该表项;
	ConId* ptr;
	ConId* lastptr;
	lastptr = headptr;
	ptr = headptr->nextptr;
	while (ptr) {
		if (buf[0] == ptr->convertID[0] && buf[1] == ptr->convertID[1]) {
			//找到
			buf[0] = ptr->clientID[0];
			buf[1] = ptr->clientID[1];
			client = ptr->addr;
			//删除
			lastptr->nextptr = ptr->nextptr;
			if (ptr == tailptr) {
				tailptr = lastptr;
			}

			char ip[20];
			
			if (flag_whether_cache) {
				if (ptr->LRU_cache >= 0) {
					if (get_IP_From_Buf(buf, length, ip)) {//成功获取ipv4地址
						//添加ip至缓存区
						add_Cache_IP(ip, ptr->LRU_cache);
						if (dbg_flag) {
							printf("已将IP添加至缓冲区\n");
						}
					}
				}
			}
			

			free(ptr);
			//退出
			break;
		}
		ptr = ptr->nextptr;
		lastptr = lastptr->nextptr;
	}

	if (ptr) {
		if (dbg_flag) {
			printf("\n转换后的ID为：%02x %02x\n", (unsigned char)buf[0], (unsigned char)buf[1]);
		}


		//回发响应报到Client
		length = sendto(local_sock, buf, length, 0, (struct sockaddr *)&client, sizeof(client));

		//反馈
		if (length < 0) {
			printf("send back error\n");
		}
		if (dbg_flag) {
			printf("回传给Client：%s\n", inet_ntoa(client.sin_addr));
			printf("\n中继回复DNS包发送完毕\n");
		}
	}
	else {
		if (dbg_flag) {
			printf("该回复已超时，不进行回发\n");
		}
	}
	
}


//监控抓包
void monitor() {
	int length = -1;
	char buf[BUF_SIZE];
	memset(&buf, 0, BUF_SIZE);

	//进行监控接收
	length = recvfrom(local_sock, buf, BUF_SIZE, 0, (struct sockaddr*) &temp, &len_addr);
	
	//监控收到包
	if (length > 0) {
		unsigned char tage;
		int i = 0;

		//打印报文内容
		if (dbg_flag) {
			printf("\n\n********************************************************\n收到报文 ");
			printf("from：%s\n", inet_ntoa(temp.sin_addr));
		}
		if (dbg_flag == 2) {
			printf("  ");
			for (i = 0; i < length; i++)
			{
				tage = (unsigned char)buf[i];
				printf("%02x ", tage);
				if (!((i + 1) % 4)) {
					printf("  ");
				}
				if (!((i + 1) % 16)) {
					printf("\n  ");
				}
			}
		}
		
		//打印报文ID
		if (dbg_flag == 2) {
			printf("\n...报文ID：");
			for (i = 0; i < 2; i++)
			{
				tage = (unsigned char)buf[i];
				if (dbg_flag == 2) {
					printf("%02x ", tage);
				}
			}
		}
		

		//判定报文QR
		if ((unsigned char)buf[2] & 0x80) {	//QR位为1：响应报
			if (dbg_flag) {
				printf("\n...报文QR：1（响应报）");
			}
			//处理响应报
			deal_Respond(buf, length);
		}
		else {								//QR位为0：查询报
			if (dbg_flag) {
				printf("\n...报文QR：0（查询报）");
			}
			//处理查询报
			deal_Question(buf, length, temp);
		}
	}
}

//处理参数
void deal_parameters(int argc, char* argv[]) {
	int i;
	//printf("%d\n", argc);
	printf("[-n | -d | -dd] [-c] [dns_server_ipaddr] [host_file_name]\n");
	if (argc == 1) {
		return;
	}
	for (i = 1; i != argc; i++) {
		if (i == 1) {
			//printf("%s\n", argv[i]);
			if (!strcmp(argv[i], "-n")) {
				dbg_flag = 0;
				printf("Debug Level：%d\n", dbg_flag);
			}
			else if (!strcmp(argv[i], "-d")) {
				dbg_flag = 1;
				printf("Debug Level：%d\n", dbg_flag);
			}
			else if (!strcmp(argv[i], "-dd")) {
				dbg_flag = 2;
				printf("Debug Level：%d\n", dbg_flag);
			}
		}
		else if (i == 2) {
			if (!strcmp(argv[i], "-c")) {
				flag_whether_cache = 1;
				printf("服务器已启动存储区\n");
			}
		}
		else if (i == 3) {
			//printf("%s\n", argv[i]);
			memcpy(srv_ip, argv[i], strlen(argv[i]));
			printf("已设置指定DNS服务器为：%s\n", srv_ip);
		}
		else if (i == 4) {
			//printf("%s\n", argv[i]);
			memcpy(host_file, argv[i], strlen(argv[i]));
			printf("已设置指定本地配置文件为：%s\n", host_file);
		}
		else {
			return;
		}
	}
	return;
}

/**************************************** Main ****************************************/
int main(int argc, char* argv[])
{
	deal_parameters(argc, argv);

	WSAStartup(MAKEWORD(2, 2), &wsaData);
	local_sock = socket(AF_INET, SOCK_DGRAM, 0);
	outside_sock = socket(AF_INET, SOCK_DGRAM, 0);

	len_addr = sizeof(struct sockaddr_in);

	if (local_sock < 0 || outside_sock < 0) {
		printf("create socket error");	
		return -1;
	}
	local_addr.sin_family = AF_INET;
	local_addr.sin_port = htons(SRV_PORT);
	local_addr.sin_addr.S_un.S_addr = INADDR_ANY;

	outside_addr.sin_family = AF_INET;
	outside_addr.sin_port = htons(SRV_PORT);
	outside_addr.sin_addr.S_un.S_addr = inet_addr(srv_ip);

	int const_one = 1;
	ioctlsocket(outside_sock, FIONBIO, (u_long FAR*) & const_one);	//将外部套接口设置为非阻塞
	ioctlsocket(local_sock, FIONBIO, (u_long FAR*) & const_one);	//将本地套接口设置为非阻塞
	
	setsockopt(local_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&const_one, sizeof(const_one));//53端口强制复用
	if (bind(local_sock, (struct sockaddr*) & local_addr, sizeof(local_addr)) < 0) {//绑定local_sock套接字到53端口
		printf("bind error");	
	}
	else {
		printf("Bind Local Socket with port 53 SUCCESS!\n");
	}

	local_Init();
	while (1) {
		monitor();
	}
}