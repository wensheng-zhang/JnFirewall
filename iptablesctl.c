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
	char cltip[32];
	char srcip[32];
	int srcport;
	char srcmac[32];
	char dstip[32];
	int dstport;
	char dstmac[32];
}USER_RULE;

const int N = 300;

FILE *fLog = NULL;
static char NICs[NIC_NUM][NIC_NAME_LENTH_MAX];

void ShowForm();
int Protocal();
int PktProc();
int IsValidIPV4(const char* ipv4);
int IsValidMac(const char* mac);
void DisplayPREROUTING();
int GetTargetRule(char *line, TARGET_RULE *ruleBuf);
void QueryNICs(void);
int QueryIPAddrByIface(const char *interface, char *IPAddr, unsigned int lenIp);
void QueryRules(void);
int GetUserInputData(USER_RULE *userRule);
int AddTarget(const USER_RULE *target);
int DeleteTargets();
void SavePermanently();


int cgiMain() {
	/* Send the content type, letting the browser know this is HTML */
	cgiHeaderContentType("text/html;charset=utf-8\n");
	/* Top of the page */
	fprintf(cgiOut, "<HTML><HEAD>\n");
	fprintf(cgiOut, "<TITLE>端口映射</TITLE></HEAD>\n");
	fprintf(cgiOut, "<BODY><H1>端口映射</H1>\n");
	fLog = fopen("/tmp/log", "a");
    QueryNICs();
	fprintf(fLog, "QueryNICs finish.\n");
    /* Now show the form */
	ShowForm();
	/* Finish up the page */
	fprintf(cgiOut, "</BODY></HTML>\n");
	fclose(fLog);
	return 0;
}

char *protocals[] = {
	"tcp",
	"udp",
	"tdplit",
	"icmp",
	"icmpv6",
	"esp",
	"ah",
	"sctp",
	"mh",
    "all"
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
	fprintf(cgiOut, "</select>\n");
	fprintf(cgiOut, "<br>\n");

	// (2)报文处理
	//fprintf(cgiOut, "报文处理:\n");
	//fprintf(cgiOut, "<input type=\"radio\" name=\"pktProc\" value=\"DROP\"checked>丢弃\n");
	//fprintf(cgiOut, "<input type=\"radio\" name=\"pktProc\" value=\"ACCEPT\">通过\n");

	// (3)客户端、源和目的信息
	fprintf(cgiOut, "<p>\n");
	fprintf(cgiOut, "<table border=\"1\">\n");
	
	fprintf(cgiOut, "<tr>\n");
	fprintf(cgiOut, "<td>客户端IP:</td>\n");
	fprintf(cgiOut, "<td><input name=\"cltip\" value=\"\"></td>\n");
	fprintf(cgiOut, "</tr>\n");

	// 出口网卡
	fprintf(cgiOut, "<tr>\n");
	fprintf(cgiOut, "<td>出口设备:</td>\n");
	fprintf(cgiOut, "<td><select name=\"outdev\">\n");
	for (i = 0; strlen(NICs[i])>0 && i < NIC_NUM; ++i){
		fprintf(cgiOut, "<option value=\"%s\">%s\n", NICs[i], NICs[i]);
	}
	fprintf(cgiOut, "</select></td>\n");
	// 出口网卡端口号
	fprintf(cgiOut, "<td>出口设备端口:</td>\n");
	fprintf(cgiOut, "<td><input name=\"outport\" value=\"\"></td>\n");
	fprintf(cgiOut, "</tr>\n");
	
	// 被映射内部信息
	fprintf(cgiOut, "<tr>\n");
	fprintf(cgiOut, "<td>内部IP:</td>\n");
	fprintf(cgiOut, "<td><input name=\"dstip\" value=\"\"></td>\n");
	fprintf(cgiOut, "<td>内部端口:</td>\n");
	fprintf(cgiOut, "<td><input name=\"dstport\" value=\"\"></td>\n");
	fprintf(cgiOut, "</tr>\n");
    fprintf(cgiOut, "</table>\n");
	fprintf(cgiOut, "<p>\n");

	fprintf(cgiOut, "<input type=\"submit\" name=\"add\" value=\"添加\">\n");
	//fprintf(cgiOut, "<input type=\"submit\" name=\"modify\" value=\"修改\">\n");
	fprintf(cgiOut, "<hr/>\n");

	if (cgiFormSubmitClicked("add") == cgiFormSuccess) {
		// Add target
	    memset(&userRule, 0, sizeof(USER_RULE));
		GetUserInputData(&userRule);
		fprintf(fLog, "protocal:%d, pktProc:%d, cltip:%s, srcip:%s, srcport:%d, srcmac:%s, dstip:%s, dstport:%d, dstmac:%s\n",
		    userRule.protocal, userRule.pktProc, userRule.cltip, userRule.srcip, userRule.srcport, userRule.srcmac,
		    userRule.dstip, userRule.dstport, userRule.dstmac);
        fflush(fLog);
		if(AddTarget(&userRule) != 0) {
			fprintf(fLog, "%s AddTarget fail\n", __FUNCTION__);
		}
	} else if (cgiFormSubmitClicked("modify") == cgiFormSuccess) {
		// Modify target
	} else if (cgiFormSubmitClicked("delete") == cgiFormSuccess) {
		// delete target
		if (DeleteTargets() != 0) {
			fprintf(fLog, "%s DeleteTargets fail\n", __FUNCTION__);
		}
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
    fprintf(cgiOut, "<hr/>\n");
	fprintf(cgiOut, "<input type=\"submit\" name=\"save\" value=\"保存\">\n");

	fprintf(cgiOut, "</form>\n");
}

int IsValidIPV4(const char* ipv4){
	int a,b,c,d;
	char temp[31];
	if (NULL == ipv4 || strlen(ipv4) == 0){	// 不设定ip地址 (即：0.0.0.0/0 anywhere)
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
	fprintf(cgiOut, "<table border=\"1\">\n");
	// 显示表头
	fprintf(cgiOut, "<tr style=\"background-color:#00FF00\">\n");
	fprintf(cgiOut, "<td> </td>\n");
	fprintf(cgiOut, "<td>序号</td>\n");
	fprintf(cgiOut, "<td>规则</td>\n");
	fprintf(cgiOut, "<td>协议</td>\n");
	fprintf(cgiOut, "<td>客户端IP</td>\n");
	fprintf(cgiOut, "<td>源IP</td>\n");
	fprintf(cgiOut, "<td>源端口</td>\n");
	fprintf(cgiOut, "<td>源Mac</td>\n");
	fprintf(cgiOut, "<td>源NIC</td>\n");
	fprintf(cgiOut, "<td>目的IP</td>\n");
	fprintf(cgiOut, "<td>目的端口</td>\n");
	fprintf(cgiOut, "<td>目的Mac</td>\n");
	fprintf(cgiOut, "<td>目的NIC</td>\n");
	fprintf(cgiOut, "</tr>\n");
	// 显示内容
	QueryRules();
	fprintf(cgiOut, "</table>\n");
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
    //fprintf(fLog, "%s ifconfig popen success.\n", __FUNCTION__);
	memset(NICs, 0, sizeof(char)*NIC_NUM*NIC_NAME_LENTH_MAX);	
	while (fgets(line, sizeof(line)-1, fp) != NULL && i < NIC_NUM){
        if (0 ==  i) {
             ++i;
             continue; // 第一行为表头
        }
        //fprintf(fLog, "%s line:%s\n", __FUNCTION__, line);
		result = strtok(line, delims);
		if (NULL != result && strcmp(result, "lo") != 0){
            //fprintf(fLog, "%s NIC:%d, Name:%s\n", __FUNCTION__, i, result);
			strncpy(NICs[i-1], result, strlen(result));
			++i;
		}
	}
    pclose(fp);
}

// 根据网卡名称，查找该网卡的ip地址
int QueryIPAddrByIface(const char *interface, char *ipaddr, unsigned int lenIp){
	FILE *fp;
	char line[N];
	char sysCmd[64];
	char *result = NULL;
	char delims[] = " ";
	int i = 0;

	if (NULL == interface || NULL == ipaddr || lenIp < 7) {
		fprintf(fLog, "%s param is invalid.", __FUNCTION__);
		return -1;
	}
	memset(sysCmd, 0, sizeof(char)*64);
	sprintf(sysCmd, "ip -4 address show dev %s", interface);
	if ((fp =popen(sysCmd, "r")) == NULL){
		fprintf(fLog, "%s ifconfig fail.\n", __FUNCTION__);
		return -1;
	}

	memset(line, 0, sizeof(char)*N);
	while (fgets(line, sizeof(line)-1, fp) != NULL){
		result = strtok(line, delims);
		if (NULL != result && strcmp(result, "inet") == 0) {
			result = strtok(NULL, delims);	// ip address (inet 192.168.0.222/24)
			if (NULL != result && strlen(result) < lenIp + 3) {
                while(i < strlen(result) && *(result + i) != '/'){
                    ipaddr[i] = *(result + i);
                    ++i;
                }
                ipaddr[i] = '\0';
                fprintf(fLog, "%s result is %s", __FUNCTION__, ipaddr);
				return 0;
			}
		}
	}

	return -1;
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
	
	for (j = 0; j < i-2 && i > 2; j++){
		fprintf(cgiOut, "<tr>\n");
		fprintf(cgiOut, "<td><input type=\"checkbox\" name=\"rule\" value=\"%d\"></td>\n", targetRules[j].seqNo);
		fprintf(cgiOut, "<td>%d</td>\n", targetRules[j].seqNo);
		fprintf(cgiOut, "<td>%s</td>\n", targetRules[j].target);
		fprintf(cgiOut, "<td>%s</td>\n", targetRules[j].protocal);
		fprintf(cgiOut, "<td>%s</td>\n", targetRules[j].cltip);
		fprintf(cgiOut, "<td>%s</td>\n", targetRules[j].srcip);
		fprintf(cgiOut, "<td>%d</td>\n", targetRules[j].srcport);
		fprintf(cgiOut, "<td>%s</td>\n", targetRules[j].srcmac);
		fprintf(cgiOut, "<td>%s</td>\n", "");
		fprintf(cgiOut, "<td>%s</td>\n", targetRules[j].dstip);
		fprintf(cgiOut, "<td>%d</td>\n", targetRules[j].dstport);
		fprintf(cgiOut, "<td>%s</td>\n", targetRules[j].dstmac);
		fprintf(cgiOut, "<td>%s</td>\n", "");
		fprintf(cgiOut, "</tr>\n");			
	}
	pclose(fp);
}

int GetUserInputData(USER_RULE *userRule){
	int res;
	int outdev = 0;
    char *nicPointers[NIC_NUM];
    int nicCnt = 0;
	char ipaddr[32];
    if (NULL == userRule){
		fprintf(fLog, "%s param is null.\n", __FUNCTION__);
		return -1;
	}
	userRule->protocal = Protocal();
    //userRule->pktProc = PktProc();
    res = cgiFormString("cltip", userRule->cltip, 32);
	if (res != cgiFormSuccess && res != cgiFormEmpty){
		fprintf(fLog, "%s cltip error.\n", __FUNCTION__);
		return -1;
	}
    while(nicCnt < NIC_NUM && strlen(NICs[nicCnt]) > 0){
        nicPointers[nicCnt] = NICs[nicCnt];
        ++nicCnt;
    }
    res = cgiFormSelectSingle("outdev", nicPointers, nicCnt, &outdev, 0);
    if (res != cgiFormSuccess){
        fprintf(fLog, "%s outdev error.\n", __FUNCTION__);
        return -1;
    }
    res = QueryIPAddrByIface(NICs[outdev], ipaddr, 32);
	if (0 != res) {
		fprintf(fLog, "%s QueryIPAddrByIface fail.\n", __FUNCTION__);
		return -1;
	}
	strncpy(userRule->srcip, ipaddr, strlen(ipaddr));	
	if (cgiFormInteger("outport", &userRule->srcport, 0) != cgiFormSuccess){
		fprintf(fLog, "%s outport error.\n", __FUNCTION__);
		return -1;
	}
/*	if (cgiFormString("srcmac", userRule->srcmac, 32) != cgiFormSuccess){
		fprintf(fLog, "%s srcmac error.\n", __FUNCTION__);
		return -1;
	}*/
	if (cgiFormString("dstip", userRule->dstip, 32) != cgiFormSuccess){
		fprintf(fLog, "%s dstip error.\n", __FUNCTION__);
		return -1;
	}
	if (cgiFormInteger("dstport", &userRule->dstport, 0) != cgiFormSuccess){
		fprintf(fLog, "%s dstport error.\n", __FUNCTION__);
		return -1;
	}
/*	if (cgiFormString("dstmac", userRule->dstmac, 32) != cgiFormSuccess){
		fprintf(fLog, "%s dstmac error.\n", __FUNCTION__);
		return -1;
	}*/

	return 0;
}

int AddTarget(const USER_RULE *target){
	char command[128] = {0};
	char cltip[32] = {0};
	char srcip[32] = {0};
    char line[N];
	FILE *fp = NULL;
	if (NULL == target 
		|| 0 != IsValidIPV4(target->cltip)|| 0 != IsValidIPV4(target->srcip) || 0 != IsValidIPV4(target->dstip)
		|| 0 >= target->srcport || 65535 < target->srcport
		|| 0 >= target->dstport || 65535 < target->dstport) {
//		|| 0 != IsValidMac(target->srcmac) || 0 != IsValidMac(target->dstmac)) {
		fprintf(fLog, "%s param is invalid.\n", __FUNCTION__);
		return -1;
	}
	if (strlen(target->cltip) != 0){
		sprintf(cltip, "-s %s", target->cltip);
	}
	if (strlen(target->srcip) != 0){
		sprintf(srcip, "-d %s", target->srcip);
	}
		
//iptables -t nat -I PREROUTING -s 192.168.0.100 -d 192.168.0.78 -p tcp -m tcp --dport 8000 -j DNAT --to-destination 10.1.0.5:8080
	sprintf(command, "iptables -t nat -I PREROUTING %s %s -p %s --dport %d -j DNAT --to-destination %s:%d", 
		cltip, srcip, protocals[target->protocal], target->srcport, target->dstip, target->dstport);
	if((fp = popen(command, "r")) == NULL){
        fprintf(fLog, "%s %s=>popen fail.\n", __FUNCTION__, command);
        return -1;
	}else if (fgets(line, sizeof(line)-1, fp) != NULL){
        fprintf(fLog, "%s %s=>execute iptables fail.\n", __FUNCTION__, command);
        return -1;
    }else{
        fprintf(fLog, "%s %s=>execute iptables success.\n", __FUNCTION__, command);
        sleep(1);
	    return 0;
    } 
}

int DeleteTargets(){
	char line[N];
	const int checkboxValueLen = 8;
    FILE *fp = NULL;
	int i = 0; 
	int count = 0;
	int result;
	int invalid;
    char sysCommand[64] = { 0 };
    sprintf(sysCommand, "%s", "iptables -t nat -nvL PREROUTING --line-number");
	
    if((fp = popen(sysCommand, "r")) == NULL){
		fprintf(fLog, "%s iptables PREROUTING fail.\n", __FUNCTION__);
		pclose(fp);
        return -1;
	}
	
	while (fgets(line, sizeof(line)-1, fp) != NULL) {
		++count;
	}
	if (count < 3){
		fprintf(fLog, "%s No target is in Chain PREROUTING\n", __FUNCTION__);
		pclose(fp);
		return -1;
	}
	
    count -= 2;     //删除查询结果的前两行

	int *deletedChoices = (int *)malloc(count * sizeof(int));
	memset(deletedChoices, 0, count * sizeof(int));
	
	char **lstTargets = (char**)malloc(count * sizeof(char*));
	for (i = 0; i < count; ++i){
		lstTargets[i] = (char*) malloc(checkboxValueLen * sizeof(char));
		memset(lstTargets[i], 0, checkboxValueLen * sizeof(char) );
		sprintf(lstTargets[i], "%d", i+1);
	}
	
	result = cgiFormCheckboxMultiple("rule", lstTargets, count, 
		deletedChoices, &invalid);
	// 进行删除操作
	do{
		if (result == cgiFormNotFound) {
			fprintf(fLog, "%s Nothing is selected.\n", __FUNCTION__);
			break;
		} else {
            fprintf(fLog, "%s Items of deleting is:", __FUNCTION__);
            for (i = 0; i < count; ++i){
                fprintf(fLog, " %d ", deletedChoices[i]);
            }
            fprintf(fLog, "\n");
            fflush(fLog); 
			for (i = count-1; i >= 0; --i){
				if (1 == deletedChoices[i]){
					memset(sysCommand, 0, 64);
					sprintf(sysCommand, "iptables -t nat -D PREROUTING %d", i+1);
					if((fp = popen(sysCommand, "r")) == NULL){
						fprintf(fLog, "%s %s => popen fail.\n", __FUNCTION__, sysCommand);
					} else if (fgets(line, sizeof(line)-1, fp) != NULL) {
                        fprintf(fLog, "%s %s => execute commmand fail.\n", __FUNCTION__, sysCommand);
                    } else {
                        fprintf(fLog, "%s %s => execute commmand success.\n", __FUNCTION__, sysCommand);
                    }                    
				}
			}
		}		
	}while (0);

	for (i = 0; i < count; ++i){
		free(lstTargets[i]);
	}
	free(lstTargets);
	free(deletedChoices);

	pclose(fp);

    return 0;
}

void SavePermanently() {
    FILE *fp = NULL;
   
	char sysCommand[] = "iptables-save > /etc/sysconfig/iptables";
	if((fp = popen(sysCommand, "r")) == NULL){
        fprintf(fLog, "%s save iptables result is null.\n", __FUNCTION__);
        return;
    }
}
