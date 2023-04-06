#pragma once
#if _MSC_VER >= 1600
#pragma execution_character_set("utf-8")// ��ָ���֧��VS����
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



//��̫������ͷ  
struct   ether_header {
	u_char   ether_dhost[ETHER_ADDR_LEN];
	u_char   ether_shost[ETHER_ADDR_LEN];
	u_short   ether_type;  //�����һ��ΪIPЭ�顣��ether_type��ֵ����0x0800  
};

//IP����ͷ  
struct ip_header  //С��ģʽ  
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

//tcp����ͷ  
struct tcp_header //С��ģʽ  
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

//tcp��udp����У���αͷ
struct psd_header {
	u_int32_t   sourceip;       //ԴIP��ַ  
	u_int32_t   destip;         //Ŀ��IP��ַ  
	u_char      mbz;            //�ÿ�(0)  
	u_char      ptcl;           //Э������  
	u_int16_t   plen;           //TCP/UDP���ݰ��ĳ���(����TCP/UDP��ͷ�������ݰ������ĳ��� ��λ:�ֽ�)  
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
	void packetSignal(QString info);	// ����������Ϣ���ź�
	void packetStaticSignal(QString info);	// �ڲ�������Ϣ�ź�
	void connStatusSignal(int connFlag);
	void connStatusStaticSignal(int connFlag);
	void recvMsgSignal();
private slots:
	void packetStaticSlot(QString info);	// �ڲ��ۺ���
	void connStatusStaticSlot(int connFlag);
	void recvMsgSlot();


private:
	//���������ݰ�  
	static void send_packet_handle(void* arg);
	//����������ݰ�, pcap_loop�������ڻص�  
	static void my_pcap_handler(u_char *user, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
	static unsigned short do_check_sum(void* buffer, int len);
	static char* uint_to_addr(u_int addr);
	static unsigned short in_cksum(unsigned short* buffer, int size);


};
