#include <stdio.h>
#include "cgic.h"
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

#define NIC_NUM  12
#define NIC_NAME_LENTH_MAX 32

// 从防火墙取上的规则
typedef struct _TARGET_RULE{
	int seqNo;
	char target[64];
	char protocal[16];
	char cltip[32];
	char srcip[32];
	unsigned short srcport;
	char srcmac[32];
	char dstip[32];
	unsigned short dstport;
	char dstmac[32];
}TARGET_RULE;

// 用户设定的规则
typedef struct _USER_RULE{
	int protocal;
	int pktProc;
	char srcip[32];
	int srcport;
	char srcmac[32];
	char dstip[32];
	int dstport;
	char dstmac[32];
}USER_RULE;

const int N = 300;

FILE *fLog = NULL;
char NICs[NIC_NUM][NIC_NAME_LENTH_MAX];

void ShowForm();
int Protocal();
int PktProc();
int IsValidIPV4(const char* ipv4);
int IsValidMac(const char* mac);
void DisplayPREROUTING();
int GetTargetRule(char *line, TARGET_RULE *ruleBuf);
void QueryNICs(void);
void QueryRules(void);
int GetUserInputData(USER_RULE *userRule);
int AddTarget(const USER_RULE *target);
void SavePermanently();


int cgiMain() {
	/* Send the content type, letting the browser know this is HTML */
	cgiHeaderContentType("text/html;charset=utf-8\n");
	/* Top of the page */
	fprintf(cgiOut, "<HTML><HEAD>\n");
	fprintf(cgiOut, "<TITLE>端口映射</TITLE></HEAD>\n");
	fprintf(cgiOut, "<BODY><H1>端口映射</H1>\n");
	fLog = fopen("/tmp/log", "w");
    QueryNICs();
	fprintf(fLog, "QueryNICs finish.\n");
    /* Now show the form */
	ShowForm();
	/* Finish up the page */
	fprintf(cgiOut, "</BODY></HTML>\n");
	fprintf(fLog, "HTML End!!!\n");
	fclose(fLog);
	return 0;
}

char *protocals[] = {
	"all",
	"tcp",
	"udp",
	"tdplit",
	"icmp",
	"icmpv6",
	"esp",
	"ah",
	"sctp",
	"mh"
};

int Protocal() {
	int protocalChoice = -1;
	cgiFormSelectSingle("protocal", protocals, 10, &protocalChoice, 0);
	return protocalChoice;
}	 

char *pktProcs[] = {
	"DROP",
	"ACCEPT"
};

int PktProc() {
	int pktProcChoice = -1;
	/* Approach #1: check for one of several valid responses. 
		Good if there are a short list of possible button values and
		you wish to enumerate them. */
	cgiFormRadio("pktProc", pktProcs, 2, &pktProcChoice, 0);
	return pktProcChoice;
}

void ShowForm()
{
	USER_RULE userRule;
	int i = 0;
	
	fprintf(cgiOut, "<!-- 2.0: multipart/form-data is required for file uploads. -->");
	fprintf(cgiOut, "<form method=\"POST\" enctype=\"multipart/form-data\" ");
	fprintf(cgiOut, "	action=\"");
	cgiValueEscape(cgiScriptName);
	fprintf(cgiOut, "\">\n");
	fprintf(cgiOut, "<p>\n");
	// (1)协议选择
    fprintf(cgiOut, "协议:\n");
	//fprintf(cgiOut, "<br>\n");
	fprintf(cgiOut, "<select name=\"protocal\">\n");
	for (i = 0; i < sizeof(protocals)/sizeof(char*); ++i){
		fprintf(cgiOut, "<option value=\"%s\">%s\n", protocals[i], protocals[i]);
	}
	/*	fprintf(cgiOut, "<option value=\"all\">all\n");
	fprintf(cgiOut, "<option value=\"tcp\">tcp\n");
	fprintf(cgiOut, "<option value=\"udp\">udp\n");
	fprintf(cgiOut, "<option value=\"tdplit\">udplit\n");
	fprintf(cgiOut, "<option value=\"icmp\">icmp\n");
	fprintf(cgiOut, "<option value=\"icmpv6\">icmpv6\n");
	fprintf(cgiOut, "<option value=\"esp\">esp\n");
	fprintf(cgiOut, "<option value=\"ah\">ah\n");
	fprintf(cgiOut, "<option value=\"sctp\">sctp\n");
	fprintf(cgiOut, "<option value=\"mh\">mh\n");*/
	fprintf(cgiOut, "</select>\n");
	fprintf(cgiOut, "<br>\n");

	// (2)报文处理
	fprintf(cgiOut, "报文处理:\n");
	fprintf(cgiOut, "<input type=\"radio\" name=\"pktProc\" value=\"DROP\"checked>丢弃\n");
	fprintf(cgiOut, "<input type=\"radio\" name=\"pktProc\" value=\"ACCEPT\">通过\n");

	// (3)源和目的信息
	fprintf(cgiOut, "<p>\n");
	fprintf(cgiOut, "源IP:\n");
	fprintf(cgiOut, "<input name=\"srcip\" value=\"\">\n");
	fprintf(cgiOut, "源端口:\n");
	fprintf(cgiOut, "<input name=\"srcport\" value=\"\">\n");
	fprintf(cgiOut, "源Mac:\n");
	fprintf(cgiOut, "<input name=\"srcmac\" value=\"\">\n");
	fprintf(cgiOut, "源NIC:\n");
	fprintf(cgiOut, "<select name=\"protocal\">\n");
	for (i = 0; strlen(NICs[i])>0 && i < NIC_NUM; ++i){
		fprintf(cgiOut, "<option value=\"%s\">%s\n", NICs[i], NICs[i]);
	}
	fprintf(cgiOut, "</select>\n");	
	fprintf(cgiOut, "<br>\n");
	
	fprintf(cgiOut, "目的IP:\n");
	fprintf(cgiOut, "<input name=\"dstip\" value=\"\">\n");
	fprintf(cgiOut, "目的端口:\n");
	fprintf(cgiOut, "<input name=\"dstport\" value=\"\">\n");
	fprintf(cgiOut, "目的Mac:\n");
	fprintf(cgiOut, "<input name=\"dstmac\" value=\"\">\n");
	fprintf(cgiOut, "目的NIC:\n");
	fprintf(cgiOut, "<select name=\"protocal\">\n");
	for (i = 0; strlen(NICs[i])>0 && i < NIC_NUM; ++i){
		fprintf(cgiOut, "<option value=\"%s\">%s\n", NICs[i], NICs[i]);
	}
	fprintf(cgiOut, "</select>\n");	
	fprintf(cgiOut, "<br>\n");

	fprintf(cgiOut, "<p>\n");
	fprintf(cgiOut, "<input type=\"submit\" name=\"add\" value=\"添加\">\n");
	fprintf(cgiOut, "<input type=\"submit\" name=\"modify\" value=\"修改\">\n");
	fprintf(cgiOut, "<br>\n");

	/* If a submit button has already been clicked, act on the 
		submission of the form. */
	if (cgiFormSubmitClicked("add") == cgiFormSuccess) {
		// Add target
        fprintf(fLog, "add button \n");
		GetUserInputData(&userRule);
        fprintf(fLog, "add button getuserinputdata. \n");
		fprintf(cgiOut, "protocal:%d, pktProc:%d, srcip:%s, srcport:%d, srcmac:%s, dstip:%s, dstport:%d, dstmac:%s\n",
		    userRule.protocal, userRule.pktProc, userRule.srcip, userRule.srcport, userRule.srcmac,
		    userRule.dstip, userRule.dstport, userRule.dstmac);
		//fprintf(cgiOut, "<p>\n");
		//AddTarget(const USER_RULE *target);
	} else if (cgiFormSubmitClicked("modify") == cgiFormSuccess) {
		// Modify target
	} else if (cgiFormSubmitClicked("delete") == cgiFormSuccess) {
		// delete target
	} else if (cgiFormSubmitClicked("save") == cgiFormSuccess) {
		// permanently preserve
		SavePermanently();
	}
	
	// (4)规则列表
	fprintf(cgiOut, "<p>\n");
	
	// 显示PREROUTING的列表
	DisplayPREROUTING();
	fprintf(cgiOut, "<p>\n");
	fprintf(cgiOut, "<input type=\"submit\" name=\"delete\" value=\"删除\">\n");

	fprintf(cgiOut, "<p>\n");
	fprintf(cgiOut, "<p>\n");
	fprintf(cgiOut, "<input type=\"submit\" name=\"save\" value=\"保存\">\n");

	fprintf(cgiOut, "</form>\n");
	fprintf(fLog, "form end! \n");
}

int IsValidIPV4(const char* ipv4){
	int a,b,c,d;
	char temp[31];
	if (NULL == ipv4){	// 不设定ip地址 (即：0.0.0.0/0 anywhere)
		fprintf(fLog, "%s param is NULL.\n", __FUNCTION__);
		return 0;
	}	
	if(sscanf(ipv4, "%d.%d.%d.%d ", &a, &b, &c, &d) == 4
		&& a>=0 && a<=255 && b>=0 && b<=255 &&
		c>=0 && c<=255 && d>=0 && d<=255){
		sprintf(temp, "%d.%d.%d.%d", a, b, c, d);
		if(strcmp(temp,ipv4)==0){  
			return 0;
		}	
	} 
	fprintf(fLog, "%s Invalid ipv4 addr:%s.\n", __FUNCTION__, ipv4);
	return -1;
}

int IsValidMac(const char* mac){
	int a,b,c,d,e,f;
    int i = 0;
	char temp[32] = {0};
    char sprtf[32] = {0};
	if (NULL == mac){	// 不设定mac地址
		fprintf(fLog, "%s param is NULL.\n", __FUNCTION__);
		return 0;
	}
	strncpy(temp, mac, strlen(mac));
	for (i=0;i<strlen(temp);i++)  // 大写字母转换为小写字母
		if((temp[i]>='A') && (temp[i]<='Z'))
			temp[i] |= 0x20;
	if (sscanf(temp, "%x:%x:%x:%x:%x:%x", &a, &b, &c, &d, &e, &f) == 6){
		sprintf(sprtf, "%x:%x:%x:%x:%x:%x", a, b, c, d, e, f);
		if (strcmp(temp, sprtf) == 0){
			return 0;			
		}
	}else if (sscanf(temp, "%x-%x-%x-%x-%x-%x", &a, &b, &c, &d, &e, &f) == 6){
		sprintf(sprtf, "%x-%x-%x-%x-%x-%x", a, b, c, d, e, f);
		if (strcmp(temp, sprtf) == 0){
			return 0;			
		}
	}else if  (sscanf(temp, "%2x%2x%2x%2x%2x%2x", &a, &b, &c, &d, &e, &f) == 6){
		sprintf(sprtf, "%2x%2x%2x%2x%2x%2x", a, b, c, d, e, f);
		if (strcmp(temp, sprtf) == 0){
			return 0;			
		}
	}
	fprintf(fLog, "%s Invalid mac addr:%s.\n", __FUNCTION__, mac);
	return -1;
}


void DisplayPREROUTING() {
	// 显示表头
	
	// 显示内容
	QueryRules();
	
}

int GetTargetRule(char *line, TARGET_RULE *ruleBuf)
{
	if (NULL == line || NULL == ruleBuf)
		return -1;
//# iptables -t nat -nvL PREROUTING --line-number
//Chain PREROUTING (policy ACCEPT 5232 packets, 601K bytes)
//num   pkts bytes target     prot opt in     out     source               destination
/*1		   2 	3	4			5	6  7	  8			9					10					11	12		13*/
//1        4   208 DNAT       tcp  --  *      *       0.0.0.0/0            192.168.0.78         tcp dpt:80 to:10.1.0.5:8080

	char delims[] = " ";
    char *result = NULL;
	char *dst = NULL;
	char *find = NULL;
	int i = 0;
	int j = 0;
	int count = 0;
	char port[8] = {0};
	char rmlinebreak[32] = {0};  // 删除换行符
    result = strtok(line, delims);
    while( result != NULL ){
		switch (++i){
			case 1: ruleBuf->seqNo = atoi(result); break;
			case 4: strncpy(ruleBuf->target, result, strlen(result)); break;
			case 5: strncpy(ruleBuf->protocal, result, strlen(result)); break;
			case 9: strncpy(ruleBuf->cltip, result, strlen(result)); break;
			case 10: strncpy(ruleBuf->srcip, result, strlen(result)); break;
			case 12: {
					find = strstr(result, "dpt:");
					if (find != NULL)
					{
						memset(port, 0, 8);
						count = 0;
						while ( *(find + 4 + count)>= '0' &&  *(find + 4 + count) <= '9')
							++count;
						for (j = 0; j < count; j++)
							port[j] = *(find + 4 +j);
						ruleBuf->srcport = atoi(port);
					}
					break;
				}
			case 13: {
					j = 0;
					while(j < strlen(result)){
						if (*(result + j) == '\n'){
							rmlinebreak[j] = '\0';
							break;
						}
						rmlinebreak[j] = *(result + j);
						++j;
					}	 
					dst = strtok(rmlinebreak, ":");
					j = 0;
					while (dst != NULL) {
						switch (j++) {
						    case 0: break;
							case 1: strncpy(ruleBuf->dstip, dst, strlen(dst)); break;
							case 2: ruleBuf->dstport = atoi(dst); break;
							default: break;
                        }
						dst = strtok(NULL, ":");
					}
					break;
				}
			default: break;
		}// switch
		result = strtok( NULL, delims );
    }// while( result != NULL )
	return 0;
}

// 获取设备的网卡列表
void QueryNICs(void){
	char line[N];
    FILE *fp;
	char delims[] = " ";
	char *result = NULL;
	
	char sysCommand[] = "ifconfig -a -s | column -t";
	int i = 0;
	if((fp = popen(sysCommand, "r")) == NULL){
        fprintf(fLog, "%s ifconfig result is null.\n", __FUNCTION__);
        return;
	}
    fprintf(fLog, "%s ifconfig popen success.\n", __FUNCTION__);
	memset(NICs, 0, sizeof(char)*NIC_NUM*NIC_NAME_LENTH_MAX);	
	while (fgets(line, sizeof(line)-1, fp) != NULL && i < NIC_NUM){
        if (0 ==  i) {
             ++i;
             continue; // 第一行为表头
        }
        fprintf(fLog, "%s line:%s\n", __FUNCTION__, line);
		result = strtok(line, delims);
		if (NULL != result && strcmp(result, "lo") != 0){
            fprintf(fLog, "%s NIC:%d, Name:%s\n", __FUNCTION__, i, result);
			strncpy(NICs[i-1], result, strlen(result));
			++i;
		}
	}
    pclose(fp);
}

void QueryRules(void){
    char line[N];
    FILE *fp;
	int i = 0; 
	int j = 0;
    char sysCommand[] = "iptables -t nat -nvL PREROUTING --line-number";
	TARGET_RULE targetRules[64];
	
    if((fp = popen(sysCommand, "r")) == NULL){
		fprintf(fLog, "%s iptables PREROUTING fail.\n", __FUNCTION__);
        return;
	}
	
	memset(targetRules, 0, 64*sizeof(TARGET_RULE));
    fprintf(fLog, "%s iptables Prerouting success.\n", __FUNCTION__);
    fflush(fLog);
	while ((fgets(line, sizeof(line)-1, fp) != NULL)&& (i < 64 + 2)) {
		if (i < 2) { // 前2行为表头
            i++;continue;
        }
		if (GetTargetRule(line, &(targetRules[i-2])) == 0){
			++i;
		}
	}
    fprintf(fLog, "%s All rules is gotted.\n", __FUNCTION__);
	for (j = 0; j < i-2 && i > 2; j++){
		fprintf(cgiOut, "%d,\n", targetRules[j].seqNo);
		fprintf(cgiOut, "%s,\n", targetRules[j].target);
		fprintf(cgiOut, "%s,\n", targetRules[j].protocal);
		fprintf(cgiOut, "%s,\n", targetRules[j].cltip);
		fprintf(cgiOut, "%s,\n", targetRules[j].srcip);
		fprintf(cgiOut, "%d,\n", targetRules[j].srcport);
		fprintf(cgiOut, "%s,\n", targetRules[j].srcmac);
		fprintf(cgiOut, "%s,\n", targetRules[j].dstip);
		fprintf(cgiOut, "%d,\n", targetRules[j].dstport);
		fprintf(cgiOut, "%s,\n", targetRules[j].dstmac);
		fprintf(cgiOut, "<br>\n");
	}
	fprintf(cgiOut, "<p>\n");
	pclose(fp);
}

int GetUserInputData(USER_RULE *userRule){
	if (NULL == userRule){
		fprintf(fLog, "%s param is null.\n", __FUNCTION__);
		return -1;
	}

	userRule->protocal = Protocal();
    //fprintf(fLog, "sel protocal:%d\n",userRule->protocal);	
    userRule->pktProc = PktProc();
    //fprintf(fLog, "sel pktProc:%d\n",userRule->pktProc);

	if (cgiFormString("srcip", userRule->srcip, 32) != cgiFormSuccess){
		fprintf(fLog, "%s srcip error.\n", __FUNCTION__);
		return -1;
	}
	if (cgiFormInteger("srcport", &userRule->srcport, 0) != cgiFormSuccess){
		fprintf(fLog, "%s srcport error.\n", __FUNCTION__);
		return -1;
	}
	if (cgiFormString("srcmac", userRule->srcmac, 32) != cgiFormSuccess){
		fprintf(fLog, "%s srcmac error.\n", __FUNCTION__);
		return -1;
	}
	if (cgiFormString("dstip", userRule->dstip, 32) != cgiFormSuccess){
		fprintf(fLog, "%s dstip error.\n", __FUNCTION__);
		return -1;
	}
	if (cgiFormInteger("dstport", &userRule->dstport, 0) != cgiFormSuccess){
		fprintf(fLog, "%s dstport error.\n", __FUNCTION__);
		return -1;
	}
	if (cgiFormString("dstmac", userRule->dstmac, 32) != cgiFormSuccess){
		fprintf(fLog, "%s dstmac error.\n", __FUNCTION__);
		return -1;
	}

	return 0;
}

int AddTarget(const USER_RULE *target){
	char command[128] = {0};
	if (NULL == target 
		|| 0 != IsValidIPV4(target->srcip) || 0 != IsValidIPV4(target->dstip)
		|| 0 >= target->srcport || 65535 < target->srcport
		|| 0 >= target->dstport || 65535 < target->dstport
		|| 0 != IsValidMac(target->srcmac) || 0 != IsValidMac(target->dstmac))
	{
		fprintf(fLog, "%s param is invalid.\n", __FUNCTION__);
		return -1;
	}

	sprintf(command, "iptables -t filter -I FORWARD -p %s -s %s -d %s --sport %d, --dport %d -j %s", 
		protocals[target->protocal], target->srcip, target->dstip, target->srcport, target->dstport, pktProcs[target->pktProc]);

	return 0;
}

void SavePermanently() {
    FILE *fp = NULL;

	char sysCommand[] = "service iptables save";
	if((fp = popen(sysCommand, "r")) == NULL){
        fprintf(fLog, "%s save iptables result is null.\n", __FUNCTION__);
        return;
	}
}



