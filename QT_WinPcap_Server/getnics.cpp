#include "getnics.h"

pcap_if_t* getAllNics()
{
	pcap_if_t *alldevs;
	pcap_if_t *devs;
	int i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];

	// 获取本地机器设备列表
	if (pcap_findalldevs_ex((char *)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		qDebug() << "Error in pcap_findalldevs_ex:";
		qDebug() << errbuf;
		exit(1);
	}

	return alldevs;
}