#pragma once
#if _MSC_VER >= 1600
#pragma execution_character_set("utf-8")// 该指令仅支持VS环境
#endif
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <pcap.h>  
#pragma comment(lib, "wpcap.lib")  
#pragma comment(lib, "Ws2_32.lib")
#include <QMessageBox>
#include <QDebug>
#include <QObject>
#include <process.h>
#include <thread>
#include <QThread>
#include <QRunnable>
#include <string>
#include <QNetworkInterface>
using namespace std;
#define ETHER_ADDR_LEN 6  
#define ETHERTYPE_IP            0x0800          /* IP */  



//以太网数据头  
struct   ether_header {
	u_char   ether_dhost[ETHER_ADDR_LEN];
	u_char   ether_shost[ETHER_ADDR_LEN];
	u_short   ether_type;  //如果上一层为IP协议。则ether_type的值就是0x0800  
};

//IP数据头  
struct ip_header  //小端模式  
{
	unsigned   char     ihl : 4;              //ip   header   length      
	unsigned   char     version : 4;          //version     
	u_char              tos;                //type   of   service     
	u_short             tot_len;            //total   length     
	u_short             id;                 //identification     
	u_short             frag_off;           //fragment   offset     
	u_char              ttl;                //time   to   live     
	u_char              protocol;           //protocol   type     
	u_short             check;              //check   sum     
	u_int               saddr;              //source   address     
	u_int               daddr;              //destination   address     
};

//tcp数据头  
struct tcp_header //小端模式  
{
	u_int16_t   source;
	u_int16_t   dest;
	u_int32_t   seq;
	u_int32_t   ack_seq;
	u_int16_t   res1 : 4;
	u_int16_t   doff : 4;
	u_int16_t   fin : 1;
	u_int16_t   syn : 1;
	u_int16_t   rst : 1;
	u_int16_t   psh : 1;
	u_int16_t   ack : 1;
	u_int16_t   urg : 1;
	u_int16_t   res2 : 2;
	u_int16_t   window;
	u_int16_t   check;
	u_int16_t   urg_ptr;
	u_char      data[512];
};

//tcp和udp计算校验和伪头
struct psd_header {
	u_int32_t   sourceip;       //源IP地址  
	u_int32_t   destip;         //目的IP地址  
	u_char      mbz;            //置空(0)  
	u_char      ptcl;           //协议类型  
	u_int16_t   plen;           //TCP/UDP数据包的长度(即从TCP/UDP报头算起到数据包结束的长度 单位:字节)  
};



class PacketHandle : public QThread
{
	Q_OBJECT
public:
	PacketHandle(QObject* parent = nullptr);
	PacketHandle(QString device, QString SRCIP, int SRCPORT, QObject *parent = nullptr);
	void run();
	static PacketHandle* myPacketHandle;
	void flagForCloseUI();
	void flagFordisConn();
signals:
	void packetSignal(QString info);	// 真正发送信息的信号
	void packetStaticSignal(QString info);	// 内部传递信息信号
	void connStatusSignal(int connFlag);
	void connStatusStaticSignal(int connFlag);
	void recvMsgSignal();
private slots:
	void packetStaticSlot(QString info);	// 内部槽函数
	void connStatusStaticSlot(int connFlag);
	void recvMsgSlot();


private:
	//负责发送数据包  
	static void send_packet_handle(void* arg);
	//负责接收数据包, pcap_loop参数用于回调  
	static void my_pcap_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
	static unsigned short do_check_sum(void* buffer, int len);
	static char* uint_to_addr(u_int addr);
	static unsigned short in_cksum(unsigned short* buffer, int size);


};
