#include "MainWindow.h"
#include "getnics.h"


int flag = 0;

MainWindow::MainWindow(QWidget *parent)
    : QWidget(parent)
{
	initWidget();
	showAllNics();
	// 点击连接按钮
	connect(btn_listen, &QPushButton::clicked, this, &MainWindow::listenSlot);
	// 点击断开连接按钮
	connect(btn_disConn, &QPushButton::clicked, this, &MainWindow::disconnSlot);

	connect(this, &MainWindow::destroyed, this, &MainWindow::stopThreadWhenCloseSlot);

}

/* 界面布局 */
void MainWindow::initWidget()
{
	this->setWindowTitle(tr("Server"));
	this->resize(800, 800);
	this->setStyleSheet("background-color:#C0C0C0");

	lab_SRCIP = new QLabel(tr("SRCIP:"));
	lab_SRCPORT = new QLabel(tr("SRCPORT:"));
	lab_selectNic = new QLabel(tr("Nics:"));

	line_SRCIP = new QLineEdit(this);
	line_SRCIP->setText("172.16.0.103");
	line_SRCPORT = new QLineEdit(this);
	line_SRCPORT->setText("8888");
	line_Send = new QLineEdit(this);

	box_selectNic = new QComboBox(this);
	//box_selectNic->resize(200, 10);

	btn_listen = new QPushButton(tr("listen"), this);
	btn_disConn = new QPushButton(tr("disconn"), this);
	btn_disConn->setEnabled(false);
	btn_send = new QPushButton(tr("send"), this);

	listWidget_info = new QListWidget(this);
	listWidget_info->setAlternatingRowColors(true);


	QHBoxLayout* hlayout_src = new QHBoxLayout();
	hlayout_src->addWidget(lab_SRCIP);
	hlayout_src->addWidget(line_SRCIP);
	hlayout_src->addStretch();
	hlayout_src->addWidget(lab_SRCPORT);
	hlayout_src->addWidget(line_SRCPORT);

	QHBoxLayout* hlayout_selectNic = new QHBoxLayout();
	hlayout_selectNic->addWidget(lab_selectNic);
	hlayout_selectNic->addWidget(box_selectNic);

	QHBoxLayout* hlayout_conn = new QHBoxLayout();
	hlayout_conn->addWidget(btn_listen);
	hlayout_conn->addStretch();
	hlayout_conn->addWidget(btn_disConn);

	QHBoxLayout* hlayout_listWidget = new QHBoxLayout();
	hlayout_listWidget->addWidget(listWidget_info);

	QHBoxLayout* hlayout_send = new QHBoxLayout();
	hlayout_send->addWidget(line_Send);
	hlayout_send->addWidget(btn_send);

	QVBoxLayout* vlayout_all = new QVBoxLayout(this);
	vlayout_all->addLayout(hlayout_src);
	vlayout_all->addLayout(hlayout_selectNic);
	vlayout_all->addLayout(hlayout_conn);
	vlayout_all->addLayout(hlayout_listWidget);
	vlayout_all->addLayout(hlayout_send);


}

/* 获取所有网卡 */
void MainWindow::showAllNics()
{
	pcap_if_t *alldevs = getAllNics();
	QStringList strList;

	// 遍历适配器
	for (auto i = alldevs; i != NULL; i = i->next)
	{
		QString str = "\\Device\\NPF_";
		int pos = QString::fromUtf8(i->name).indexOf(QRegExp("[{]+"));
		QString nic = QString::fromUtf8(i->name).mid(pos, -1);

		strList << str + nic;
	}

	// 显示到comboBox中
	box_selectNic->addItems(strList);

}

void MainWindow::packetSlot(QString info)
{
	listWidget_info->addItem(info);
}
void MainWindow::connStatusSlot(int connFlag)
{
	btn_listen->setEnabled(true);
	btn_disConn->setEnabled(false);
	line_SRCIP->setEnabled(true);
	line_SRCPORT->setEnabled(true);
	box_selectNic->setEnabled(true);
}

void MainWindow::disconnSlot()
{
	btn_listen->setEnabled(true);
	btn_disConn->setEnabled(false);
	line_SRCIP->setEnabled(true);
	line_SRCPORT->setEnabled(true);
	box_selectNic->setEnabled(true);

	subPacketHandle->flagFordisConn();

}

void MainWindow::stopThreadWhenCloseSlot()
{
	if (flag == 1) {
		subPacketHandle->quit();
		subPacketHandle->flagForCloseUI();
		subPacketHandle->wait();
	}
}

/* 发出点击连接按钮的信号 */
void MainWindow::listenSlot()
{

	// 设置不可用防止篡改
	btn_listen->setEnabled(false);
	btn_disConn->setEnabled(true);
	line_SRCIP->setEnabled(false);
	line_SRCPORT->setEnabled(false);
	box_selectNic->setEnabled(false);

	QString device = box_selectNic->currentText();
	int SRCPORT = (line_SRCPORT->text()).toInt();
	QString SRCIP = line_SRCIP->text();

	subPacketHandle = new PacketHandle(device, SRCIP, SRCPORT);
	connect(subPacketHandle, &PacketHandle::packetSignal, this, &MainWindow::packetSlot);
	connect(subPacketHandle, &PacketHandle::connStatusSignal, this, &MainWindow::connStatusSlot);
	subPacketHandle->start();

}
