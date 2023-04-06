#pragma once
#define WIN32
#include <QDebug>
#include "pcap.h"
#include "windows.h"
#pragma comment(lib,"wpcap.lib")

pcap_if_t* getAllNics();

