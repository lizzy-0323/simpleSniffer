// SnifferDlg.cpp: 实现文件
//lazy1
/*所有的函数我都采取int的返回值，1为正常，-1为异常*/
/*TODO:1.数据的写入
2.流量的记录*/
#pragma comment(lib,"libnet.lib")
#include "pch.h"
#include "framework.h"
#include "Sniffer.h"
#include "SnifferDlg.h"
#include "afxcmn.h"
#include "afxwin.h"
#include "afxdialogex.h"
#include"pcap.h"
#include"libnet.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#define ETH_ARP         0x0806  //以太网帧类型表示后面数据的类型，对于ARP请求或应答来说，该字段的值为x0806
#define ARP_HARDWARE    1  //硬件类型字段值为表示以太网地址
#define ETH_IP          0x0800  //协议类型字段表示要映射的协议地址类型值为x0800表示IP地址
#define ARP_REQUEST     1   //ARP请求
#define ARP_RESPONSE       2      //ARP应答
#define MAX_BUFF_LEN 65500

extern int analyze_tcp(const u_char* pkt, datapkt* data, struct pktcount* npacket);
extern int analyze_udp(const u_char* pkt, datapkt* data, struct pktcount* npacket);
extern int analyze_icmp(const u_char* pkt, datapkt* data, struct pktcount* npacket);
extern int analyze_icmp6(const u_char* pkt, datapkt* data, struct pktcount* npacket);
extern int  analyze_arp(const u_char* pkt, datapkt* data, struct pktcount* npacket);
extern int  analyze_ip6(const u_char* pkt, datapkt* data, struct pktcount* npacket);
extern int analyze_ip(const u_char* pkt, datapkt* data, struct pktcount* npacket);
extern int analyze_frame(const u_char* pkt, struct datapkt* data, struct pktcount* npacket);
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton1();
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
	ON_BN_CLICKED(IDC_BUTTON1, &CAboutDlg::OnBnClickedButton1)
END_MESSAGE_MAP()


// CSnifferDlg 对话框


/****************************功能函数*******************************/
CSnifferDlg::CSnifferDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_SNIFFER_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}
//初始化函数
int CSnifferDlg::Sniffer_initCap()
{
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "未找到网卡: %s\n", errbuf);
		exit(1);
	}
	return 1;
}
/*pkt为网络中捕获的包，data为要存为本机上的数据*/

//线程函数(copy)
DWORD WINAPI Sniffer_CapThread(LPVOID lpParameter)
{
	int res, nItem;
	struct tm* ltime;
	CString timestr, buf, srcMac, destMac;
	time_t local_tv_sec;
	struct pcap_pkthdr* header;						    //数据包头
	const u_char* pkt_data = NULL, * pData = NULL;     //网络中收到的字节流数据
	u_char* ppkt_data;

	CSnifferDlg* pthis = (CSnifferDlg*)lpParameter;
	if (NULL == pthis->m_ThreadHandle)
	{
		MessageBox(NULL, _T("线程句柄错误"), _T("提示"), MB_OK);
		return -1;
	}
	//读取一个数据包
	while ((res = pcap_next_ex(pthis->adhandle, &header, &pkt_data)) >= 0)
	{
		if (res == 0)				//超时
			continue;
		struct datapkt* data = (struct datapkt*)malloc(sizeof(struct datapkt));
		memset(data, 0, sizeof(struct datapkt));

		if (NULL == data)
		{
			MessageBox(NULL, _T("空间已满， 无法接收新的数据包"), _T("Error"), MB_OK);
			return -1;
		}

		//分析出错或所接收数据包不在处理范围内
		if (analyze_frame(pkt_data, data, &(pthis->npacket)) < 0)
			continue;

			//将数据包保存到打开的文件中
		if (pthis->dumpfile != NULL)
		{
			pcap_dump((unsigned char*)pthis->dumpfile, header, pkt_data);
		}

		//更新各类数据包计数
		pthis->Sniffer_updatePacket();

		//将本地化后的数据装入一个链表中，以便后来使用		
		ppkt_data = (u_char*)malloc(header->len);
		memcpy(ppkt_data, pkt_data, header->len);

		pthis->m_localDataList.AddTail(data);
		pthis->m_netDataList.AddTail(ppkt_data);

		/*预处理，获得时间、长度*/
		data->len = header->len;								//链路中收到的数据长度
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		data->time[0] = ltime->tm_year + 1900;
		data->time[1] = ltime->tm_mon + 1;
		data->time[2] = ltime->tm_mday;
		data->time[3] = ltime->tm_hour;
		data->time[4] = ltime->tm_min;
		data->time[5] = ltime->tm_sec;

		/*为新接收到的数据包在listControl中新建一个item*/
		buf.Format(_T("%d"), pthis->npkt);
		nItem = pthis->m_listCtrl.InsertItem(pthis->npkt, buf);

		/*显示时间戳*/
		timestr.Format(_T("%d/%d/%d  %d:%d:%d"), data->time[0],
			data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
		pthis->m_listCtrl.SetItemText(nItem, 1, timestr);

		/*显示长度*/
		buf.Empty();
		buf.Format(_T("%d"), data->len);
		pthis->m_listCtrl.SetItemText(nItem, 2, buf);

		/*显示源MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->src[0], data->ethh->src[1],
			data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
		pthis->m_listCtrl.SetItemText(nItem, 3, buf);

		/*显示目的MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->dest[0], data->ethh->dest[1],
			data->ethh->dest[2], data->ethh->dest[3], data->ethh->dest[4], data->ethh->dest[5]);
		pthis->m_listCtrl.SetItemText(nItem, 4, buf);

		/*获得协议*/
		pthis->m_listCtrl.SetItemText(nItem, 5, CString(data->pktType));

		/*获得源IP*/
		buf.Empty();
		if (0x0806 == data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_srcip[0],
				data->arph->ar_srcip[1], data->arph->ar_srcip[2], data->arph->ar_srcip[3]);
		}
		else if (0x0800 == data->ethh->type) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->saddr;
			buf = CString(inet_ntoa(in));
		}
		else if (0x86dd == data->ethh->type) {
			int n;
			for (n = 0; n < 8; n++)
			{
				if (n <= 6)
					buf.AppendFormat(_T("%02x:"), data->iph6->saddr[n]);
				else
					buf.AppendFormat(_T("%02x"), data->iph6->saddr[n]);
			}
		}
		pthis->m_listCtrl.SetItemText(nItem, 6, buf);

		/*获得目的IP*/
		buf.Empty();
		if (0x0806 == data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_destip[0],
				data->arph->ar_destip[1], data->arph->ar_destip[2], data->arph->ar_destip[3]);
		}
		else if (0x0800 == data->ethh->type) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->daddr;
			buf = CString(inet_ntoa(in));
		}
		else if (0x86dd == data->ethh->type) {
			int n;
			for (n = 0; n < 8; n++)
			{
				if (n <= 6)
					buf.AppendFormat(_T("%02x:"), data->iph6->daddr[n]);
				else
					buf.AppendFormat(_T("%02x"), data->iph6->daddr[n]);
			}
		}
		pthis->m_listCtrl.SetItemText(nItem, 7, buf);

		/*对包计数*/
		pthis->npkt++;
		/*对流量计数*/
		pthis->BYTE += (sizeof(header->len));
	}
	return 1;
}
//捕捉函数
int CSnifferDlg::Sniffer_startCap()
{
	int if_index, filter_index, count;
	u_int netmask;//获取子网掩码
	struct bpf_program fcode;//用于储存过滤规则，仅仅用于pcap_compile
	char packet_filter[] = "";
	//首先初始化
	Sniffer_initCap();
	//获得接口和过滤器索引,用于找到指定的包
	if_index = this->m_ComboBox.GetCurSel();
	filter_index = this->m_ComboBoxRule.GetCurSel();
	//错误处理
	if(0 == if_index || CB_ERR == if_index)
	{
		MessageBox(_T("请选择一个合适的网卡接口"));
		return -1;
	}
	if (CB_ERR == filter_index)
	{
		MessageBox(_T("过滤器选择错误"));
		return -1;
	}
	/*获得选中的网卡接口*/
	d = alldevs;
	for (count = 0; count < if_index - 1; count++)
	{
		d = d->next;
	}
	/* 打开适配器进行抓包 */
	if ((adhandle = pcap_open(d->name,  // 设备名
		65536,     // 要捕捉的数据包的部分 
				   // 65535保证能捕获到不同数据链路层上的每个数据包的全部内容
		PCAP_OPENFLAG_PROMISCUOUS,         // 混杂模式
		1000,      // 读取超时时间
		NULL,      // 远程机器验证
		errbuf     // 错误缓冲池
	)) == NULL)
	{
		MessageBox(_T("无法打开接口" + CString(d->description)));
		pcap_freealldevs(alldevs);//释放内存
		return -1;
	}
	/* 检查数据链路层，为了简单，我们只考虑以太网 */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		MessageBox(_T("该网络并不是以太网" ));
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (d->addresses != NULL)
		/* 获得接口第一个地址的掩码 */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* 如果接口没有地址，那么假设一个C类的掩码 */
		netmask = 0xffffff;
	//编译过滤器
	if (filter_index == 0)//如果不过滤
	{
		if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
		{
			MessageBox(_T("无法编译过滤器"));
			/* 释放设备列表 */
			pcap_freealldevs(alldevs);
			return -1;
		}
	}
	else
	{
		CString str;
		char* filter;//一个过滤器
		int len, x;
		this->m_ComboBoxRule.GetLBText(filter_index, str);//获取过滤器标号中的内容
		len = str.GetLength() + 1;
		filter = (char*)malloc(len);//为过滤器分配内容
		for (x = 0; x < len; x++)
		{
			filter[x] = str.GetAt(x);
		}
		//用过滤器过滤数据包
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) < 0)
		{
			MessageBox(_T("语法错误，无法编译过滤器"));
			pcap_freealldevs(alldevs);
			return -1;
		}
	}
	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		MessageBox(_T("过滤器设置有误"));
		/* 释放设备列表 */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/*设置过滤包存储路径*/
	CFileFind file;
	char thistime[30];
	struct tm* ltime;
	memset(filepath, 0, 512);
	memset(filename, 0, 64);

	if (!file.FindFile(_T("保存数据")))
	{
		CreateDirectory(_T("保存数据"), NULL);
	}

	time_t nowtime;//存储当前时间
	time(&nowtime);
	ltime = localtime(&nowtime);
	strftime(thistime, sizeof(thistime), "%Y%m%d %H%M%S", ltime);
	strcpy(filepath, "SavedData\\");
	strcat(filename, thistime);
	strcat(filename, ".pcap");

	strcat(filepath, filename);
	dumpfile = pcap_dump_open(adhandle, filepath);
	if (dumpfile == NULL)
	{
		MessageBox(_T("文件创建错误！"));
		return -1;
	}

	pcap_freealldevs(alldevs);

	//接收数据，新建线程处理
	LPDWORD threadCap = NULL;
	m_ThreadHandle = CreateThread(NULL, 0, Sniffer_CapThread, this, 0, threadCap);
	if (m_ThreadHandle == NULL)
	{
		int code = GetLastError();
		CString str;
		str.Format(_T("创建线程错误，代码为%d."), code);
		MessageBox(str);
		return -1;
	}
	return 1;
}
//发送函数
int CSnifferDlg::Sniffer_sendPacket()
{
	int index;
	index = m_ComboBoxPk.GetCurSel();//获得选取的序号
	unsigned char sendbuf[42]; //arp包结构大小，42个字节
	unsigned char sendbuf_tcp[1460];
	char mac[6] = { 0x00,0x11,0x22,0x33,0x44,0x55 };
	char ip[4] = { 0x01,0x02,0x03,0x04 };
	ethhdr eh;//定义各种需要的协议头
	arphdr ah;
	tcphdr th;
	udphdr uh;
	iphdr ih;
	Psdhdr psh;
	if (index == 1)
	{
		//赋值MAC地址
		memset(eh.dest, 0xff, 6);   //以太网首部目的MAC地址，全为广播地址
		memcpy(eh.src, mac, 6);   //以太网首部源MAC地址
		memcpy(ah.ar_srcmac, mac, 6);   //ARP字段源MAC地址
		memset(ah.ar_destmac, 0xff, 6);   //ARP字段目的MAC地址
		memcpy(ah.ar_srcip, ip, 4);   //ARP字段源IP地址
		memset(ah.ar_destip, 0x05, 4);   //ARP字段目的IP地址
		eh.type = htons(ETH_ARP);   //htons：将主机的无符号短整形数转换成网络字节顺序
		ah.ar_hrd = htons(ARP_HARDWARE);
		ah.ar_pro = htons(ETH_IP);
		ah.ar_hln = 6;
		ah.ar_pln = 4;
		ah.ar_op = htons(ARP_REQUEST);
		//构造一个ARP请求
		memset(sendbuf, 0, sizeof(sendbuf));   //ARP清零
		memcpy(sendbuf, &eh, sizeof(eh));
		memcpy(sendbuf + sizeof(eh), &ah, sizeof(ah));
		//如果发送成功
		if (pcap_sendpacket(adhandle, sendbuf, 42) == 0)
		{
			printf("\nPacketSend succeed\n");
			return 1;
		}
		else
		{
			printf("PacketSendPacket in getmine Error: %d\n", GetLastError());
			return -1;
		}
	}
	else
	{
		memset(eh.dest, 0xff, 6);   //以太网首部目的MAC地址，全为广播地址
		memcpy(eh.src, mac, 6);   //以太网首部源MAC地址
		eh.type = htons(ETH_IP);   //htons：将主机的无符号短整形数转换成网络字节顺序
		//ip头部部分
		ih.ihl = (4 << 4 | sizeof(ih) / sizeof(unsigned int));
		ih.tos = 0;
		ih.tlen = htons((unsigned short)(sizeof(iphdr) + sizeof(tcphdr)));
		ih.id = 1;
		ih.frag_off = 0x40;
		ih.ttl = 20;
		ih.proto = PROTO_TCP;
		ih.check = 0;
		ih.saddr = inet_addr(ip);
		ih.daddr = inet_addr("5.5.5.5");
		//tcp伪首部
		psh.saddr = ih.saddr;
		psh.daddr = ih.daddr;
		psh.mbz = 0;
		psh.ptcl = ih.proto;
		psh.plen = htons(sizeof(tcphdr));
		//tcp
		th.sport = htons(20);//源端口
		th.dport = htons(20);//目的端口
		th.seq = htonl(1);//序列号
		th.ack_seq = 1;
		th.syn = (u_char)1;//标志
		th.window = htons(400);//窗口大小
		th.check = 0;//校验和暂时设为0
		th.urg = 0;//偏移


		//填充发送缓冲区
		memset(sendbuf_tcp, 0, sizeof(sendbuf_tcp));
		memcpy(sendbuf_tcp, (void*)&eh, sizeof(eh));
		memcpy(sendbuf_tcp + sizeof(eh), (void*)&ih, sizeof(ih));
		memcpy(sendbuf_tcp + sizeof(eh) + sizeof(ih), (void*)&th, sizeof(tcphdr));
		//发送
		if (pcap_sendpacket(adhandle, sendbuf_tcp, 1460) == 0)
		{
			return 1;
		}
		else 
		{
			return -1;
		}
	}
}
//保存函数
int CSnifferDlg::Sniffer_saveFile()
{
	//用于
	CFileFind find;
	//如果没找到文件
	if (find.FindFile(CString(filepath))==NULL)
	{
		MessageBox(_T("保存文件出错"));
		return -1;
	}
	//打开文件对话框
	//保存格式设置为.pcap。以便可以使用wireshark打开
	CFileDialog  FileDlg(FALSE, _T(".pcap"), NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT);
	//设置初始位置为C://
	FileDlg.m_ofn.lpstrInitialDir = _T("c:\\");
	if (FileDlg.DoModal() == IDOK)
	{
		CopyFile(CString(filepath), FileDlg.GetPathName(), TRUE);
	}
	return 1;
}
//读取函数
int CSnifferDlg::Sniffer_readFile(CString path)
{
	int res, nItem, i;
	struct tm* ltime;
	CString timestr, buf, srcMac, destMac;
	time_t local_tv_sec;
	struct pcap_pkthdr* header;			//数据包头
	const u_char* pkt_data = NULL;     //网络中收到的字节流数据
	u_char* ppkt_data;

	CSnifferDlg* pthis = this;						
	pcap_t* fp;

	//首先处理一下路径，利用pcap_open_offline打开文件时，
	//路径需要用char *类型，不能用CString强制转换后的char *
	int len = path.GetLength() + 1; 
		char* charpath = (char*)malloc(len);
	memset(charpath, 0, len);
	if (NULL == charpath)
		return -1;

	for (i = 0; i < len; i++)
		charpath[i] = (char)path.GetAt(i);

	//打开相关文件
	if ((fp = pcap_open_offline( /*(char*)(LPCTSTR)path*/charpath, errbuf)) == NULL)
	{
		MessageBox(_T("打开文件错误") + CString(errbuf));
		return -1;
	}

	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{
		struct datapkt* data = (struct datapkt*)malloc(sizeof(struct datapkt));
		memset(data, 0, sizeof(struct datapkt));

		if (NULL == data)
		{
			MessageBox(_T("空间已满，无法接收新的数据包"));
			return  -1;
		}

		//分析出错或所接收数据包不在处理范围内
		if (analyze_frame(pkt_data, data, &(pthis->npacket)) < 0)
			continue;

		//更新各类数据包计数
		pthis->Sniffer_updatePacket();

		//将本地化后的数据装入一个链表中，以便后来使用		
		ppkt_data = (u_char*)malloc(header->len);
		memcpy(ppkt_data, pkt_data, header->len);

		pthis->m_localDataList.AddTail(data);
		pthis->m_netDataList.AddTail(ppkt_data);

		/*预处理，获得时间、长度*/
		data->len = header->len;		//链路中收到的数据长度
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		data->time[0] = ltime->tm_year + 1900;
		data->time[1] = ltime->tm_mon + 1;
		data->time[2] = ltime->tm_mday;
		data->time[3] = ltime->tm_hour;
		data->time[4] = ltime->tm_min;
		data->time[5] = ltime->tm_sec;

		/*为新接收到的数据包在listControl中新建一个item*/
		buf.Format(_T("%d"), pthis->npkt);
		nItem = pthis->m_listCtrl.InsertItem(pthis->npkt, buf);

		/*显示时间戳*/
		timestr.Format(_T("%d/%d/%d  %d:%d:%d"), data->time[0],
			data->time[1], data->time[2], data->time[3], data->time[4], data->time[5]);
		pthis->m_listCtrl.SetItemText(nItem, 1, timestr);

		/*显示长度*/
		buf.Empty();
		buf.Format(_T("%d"), data->len);
		pthis->m_listCtrl.SetItemText(nItem, 2, buf);

		/*显示源MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->src[0], data->ethh->src[1],
			data->ethh->src[2], data->ethh->src[3], data->ethh->src[4], data->ethh->src[5]);
		pthis->m_listCtrl.SetItemText(nItem, 3, buf);

		/*显示目的MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"), data->ethh->dest[0], data->ethh->dest[1],
			data->ethh->dest[2], data->ethh->dest[3], data->ethh->dest[4], data->ethh->dest[5]);
		pthis->m_listCtrl.SetItemText(nItem, 4, buf);

		/*获得协议*/
		pthis->m_listCtrl.SetItemText(nItem, 5, CString(data->pktType));

		/*获得源IP*/
		buf.Empty();
		if (0x0806 == data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_srcip[0],
				data->arph->ar_srcip[1], data->arph->ar_srcip[2], data->arph->ar_srcip[3]);
		}
		else  if (0x0800 == data->ethh->type) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->saddr;
			buf = CString(inet_ntoa(in));
		}
		else if (0x86dd == data->ethh->type) {
			int i;
			for (i = 0; i < 8; i++)
			{
				if (i <= 6)
					buf.AppendFormat(_T("%02x-"), data->iph6->saddr[i]);
				else
					buf.AppendFormat(_T("%02x"), data->iph6->saddr[i]);
			}
		}
		pthis->m_listCtrl.SetItemText(nItem, 6, buf);

		/*获得目的IP*/
		buf.Empty();
		if (0x0806 == data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"), data->arph->ar_destip[0],
				data->arph->ar_destip[1], data->arph->ar_destip[2], data->arph->ar_destip[3]);
		}
		else if (0x0800 == data->ethh->type) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->daddr;
			buf = CString(inet_ntoa(in));
		}
		else if (0x86dd == data->ethh->type) {
			int i;
			for (i = 0; i < 8; i++)
			{
				if (i <= 6)

					buf.AppendFormat(_T("%02x-"), data->iph6->daddr[i]);
				else
					buf.AppendFormat(_T("%02x"), data->iph6->daddr[i]);
			}
		}
		pthis->m_listCtrl.SetItemText(nItem, 7, buf);

		/*对包计数*/
		pthis->npkt++;
	}

	pcap_close(fp);

	return 1;
}
/*****************************************************************/
void CSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_BUTTON2, Start_Button);
	DDX_Control(pDX, IDC_BUTTON3, End_Button);
	DDX_Control(pDX, IDC_TREE1, m_treeCtrl);
	DDX_Control(pDX, IDC_LIST2, m_listCtrl);
	DDX_Control(pDX, IDC_COMBO1, m_ComboBox);
	DDX_Control(pDX, IDC_BUTTON4, Save_Button);
	DDX_Control(pDX, IDC_BUTTON1, Load_Button);
	DDX_Control(pDX, IDC_COMBO2, m_ComboBoxRule);
	DDX_Control(pDX, IDC_EDIT2, m_editNTcp);
	DDX_Control(pDX, IDC_EDIT4, m_editNHttp);
	DDX_Control(pDX, IDC_EDIT1, m_editNIpv6);
	DDX_Control(pDX, IDC_EDIT3, m_editNUdp);
	DDX_Control(pDX, IDC_EDIT5, m_editNArp);
	DDX_Control(pDX, IDC_EDIT6, m_editNIpv4);
	DDX_Control(pDX, IDC_EDIT7, m_editNIcmp);
	DDX_Control(pDX, IDC_COMBO3, m_edit);
	DDX_Control(pDX, IDC_EDIT8, m_editNOther);
	DDX_Control(pDX, IDC_EDIT9, m_editNSum);
	DDX_Control(pDX, IDC_EDIT10, m_editNflow);
	DDX_Control(pDX, IDC_BUTTON6, Send_Button);

	DDX_Control(pDX, IDC_COMBO4, m_ComboBoxPk);
}

BEGIN_MESSAGE_MAP(CSnifferDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &CSnifferDlg::OnBnClickedButton1)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST2, &CSnifferDlg::OnLvnItemchangedList2)
	ON_EN_CHANGE(IDC_EDIT1, &CSnifferDlg::OnEnChangeEdit1)
	ON_BN_CLICKED(IDC_BUTTON4, &CSnifferDlg::OnBnClickedButton4)
	ON_EN_CHANGE(TCP, &CSnifferDlg::OnEnChangeTcp)
	ON_CBN_SELCHANGE(IDC_COMBO1, &CSnifferDlg::OnCbnSelchangeCombo1)
	ON_BN_CLICKED(IDC_BUTTON2, &CSnifferDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &CSnifferDlg::OnBnClickedButton3)
	ON_EN_CHANGE(IDC_EDIT2, &CSnifferDlg::OnEnChangeEdit2)
	ON_EN_CHANGE(IDC_EDIT7, &CSnifferDlg::OnEnChangeEdit7)
	ON_EN_CHANGE(IDC_COMBO3, &CSnifferDlg::OnEnChangeCombo3)
	//ON_CBN_SELCHANGE(IDC_COMBO4, &CSnifferDlg::OnCbnSelchangeCombo4)
	ON_CBN_SELCHANGE(IDC_COMBO2, &CSnifferDlg::OnCbnSelchangeCombo2)
	ON_EN_CHANGE(IDC_EDIT4, &CSnifferDlg::OnEnChangeEdit4)
	ON_EN_CHANGE(IDC_EDIT3, &CSnifferDlg::OnEnChangeEdit3)
	ON_EN_CHANGE(IDC_EDIT5, &CSnifferDlg::OnEnChangeEdit5)
	ON_EN_CHANGE(IDC_EDIT6, &CSnifferDlg::OnEnChangeEdit6)
	ON_EN_CHANGE(IDC_EDIT9, &CSnifferDlg::OnEnChangeEdit9)
	//ON_BN_CLICKED(IDC_BUTTON5, &CSnifferDlg::OnBnClickedButton5)
	ON_EN_CHANGE(IDC_EDIT10, &CSnifferDlg::OnEnChangeEdit10)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST2, &CSnifferDlg::OnNMDblclkList2)
	ON_BN_CLICKED(IDC_BUTTON6, &CSnifferDlg::OnBnClickedButton6)
END_MESSAGE_MAP()


// CSnifferDlg 消息处理程序
//初始化对话框
BOOL CSnifferDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	m_listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

	m_listCtrl.InsertColumn(0, _T("编号"), 3, 40);                        //1表示右，2表示中，3表示左
	m_listCtrl.InsertColumn(1, _T("时间"), 3, 130);
	m_listCtrl.InsertColumn(2, _T("长度"), 3, 72);
	m_listCtrl.InsertColumn(3, _T("源MAC地址"), 3, 140);
	m_listCtrl.InsertColumn(4, _T("目的MAC地址"), 3, 140);
	m_listCtrl.InsertColumn(5, _T("协议"), 3, 70);
	m_listCtrl.InsertColumn(6, _T("源IP地址"), 3, 145);
	m_listCtrl.InsertColumn(7, _T("目的IP地址"), 3, 145);
	m_ComboBox.AddString(_T("请选择一个网卡接口(必选)"));
	m_ComboBoxRule.AddString(_T("请选择过滤规则(可选)"));
	m_ComboBoxPk.AddString(_T("请选择发送的包"));
	m_ComboBoxPk.AddString(_T("arp"));
	m_ComboBoxPk.AddString(_T("tcp"));
	//如果查找不到网卡
	if (Sniffer_initCap() < 0)
	{
		return FALSE;

	}

	/*初始化接口列表*/
	for (d = alldevs; d; d = d->next)
	{
		if (d->description)
			m_ComboBox.AddString(CString(d->description));  //Problem 1字符集问题
	}
	/*初始化过滤规则列表*/
	m_ComboBoxRule.AddString(_T("tcp"));
	m_ComboBoxRule.AddString(_T("udp"));
	m_ComboBoxRule.AddString(_T("ip"));
	m_ComboBoxRule.AddString(_T("arp"));
	m_ComboBoxRule.AddString(_T("icmp"));

	//用于设定一个过滤的初始值
	m_ComboBox.SetCurSel(0);
	m_ComboBoxRule.SetCurSel(0);
	m_ComboBoxPk.SetCurSel(0);
	End_Button.EnableWindow(FALSE);
	Save_Button.EnableWindow(FALSE);
	Send_Button.EnableWindow(FALSE);
	m_ComboBoxPk.EnableWindow(FALSE);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CSnifferDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CSnifferDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


//读取按钮
void CSnifferDlg::OnBnClickedButton1()
{

	// TODO: 在此添加控件通知处理程序代码
	//读取之前将ListCtrl清空
	this->m_listCtrl.DeleteAllItems();
	this->npkt = 1;													//列表重新计数
	this->m_localDataList.RemoveAll();				//每次一开始就将以前存的数据清空掉
	this->m_netDataList.RemoveAll();
	memset(&(this->npacket), 0, sizeof(struct pktcount));//各类包计数清空

	//打开文件对话框
	CFileDialog   FileDlg(TRUE, _T(".lix"), NULL, OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT);
	FileDlg.m_ofn.lpstrInitialDir = _T("c:\\");
	if (FileDlg.DoModal() == IDOK)
	{
		int ret = this->Sniffer_readFile(FileDlg.GetPathName());
		if (ret < 0)
			return;
	}
}

//列表更新
void CSnifferDlg::OnLvnItemchangedList2(NMHDR* pNMHDR, LRESULT* pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	int index;
	index = this->m_listCtrl.GetHotItem();

	if (index > this->m_localDataList.GetCount() - 1)
		return;

	this->Sniffer_updateInfo(index);
	this->Sniffer_updateTree(index);
	*pResult = 0;
}

void CSnifferDlg::OnEnChangeEdit1()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}
//保存按钮
void CSnifferDlg::OnBnClickedButton4()
{
	// TODO: 在此添加控件通知处理程序代码
	if (this->Sniffer_saveFile() < 0)
		return;
}
//将数据部分写入文本框中
void print_packet_hex(const u_char* pkt, int size_pkt, CString* buf)
{
	int i = 0, j = 0, rowcount;
	u_char ch;

	char tempbuf[256];
	memset(tempbuf, 0, 256);

	for (i = 0; i < size_pkt; i += 16)
	{
		buf->AppendFormat(_T("%04x:  "), (u_int)i);
		rowcount = (size_pkt - i) > 16 ? 16 : (size_pkt - i);

		for (j = 0; j < rowcount; j++)
			buf->AppendFormat(_T("%02x  "), (u_int)pkt[i + j]);

		//不足16，用空格补足
		if (rowcount < 16)
			for (j = rowcount; j < 16; j++)
				buf->AppendFormat(_T("    "));


		for (j = 0; j < rowcount; j++)
		{
			ch = pkt[i + j];
			ch = isprint(ch) ? ch : '.';
			buf->AppendFormat(_T("%c"), ch);
		}

		buf->Append(_T("\r\n"));
		if (rowcount < 16)
			return;
	}
}

void CSnifferDlg::OnEnChangeTcp()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}

void CSnifferDlg::OnCbnSelchangeCombo1()
{
	// TODO: 在此添加控件通知处理程序代码
}
//更新数据
int CSnifferDlg::Sniffer_updateInfo(int index)//更新数据
{
	//找到某一个包的数据
	POSITION localpos, netpos;
	localpos = this->m_localDataList.FindIndex(index);
	netpos = this->m_netDataList.FindIndex(index);
	//取出这个包的数据
	struct datapkt* local_data = (struct datapkt*)(this->m_localDataList.GetAt(localpos));
	u_char* net_data = (u_char*)(this->m_netDataList.GetAt(netpos));

	CString buf;
	//将这个包的数据写入buf
	print_packet_hex(net_data, local_data->len, &buf);
	//显示
	this->m_edit.SetWindowText(buf);

	return 1;
}
//更新包数据
int CSnifferDlg::Sniffer_updatePacket()
{
	CString str_num;
	str_num.Format(_T("%d"), this->npacket.n_arp);
	this->m_editNArp.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_http);
	this->m_editNHttp.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_icmp);
	this->m_editNIcmp.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_ip6);
	this->m_editNIpv6.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_other);
	this->m_editNOther.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_sum);
	this->m_editNSum.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_tcp);
	this->m_editNTcp.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_udp);
	this->m_editNUdp.SetWindowText(str_num);

	str_num.Format(_T("%d"), this->npacket.n_ip);
	this->m_editNIpv4.SetWindowText(str_num);
	//将流量数据写入
	str_num.Format(_T("%d"), this->BYTE);
	this->m_editNflow.SetWindowText(str_num);

	return 1;
}
//更新树形控件
int  CSnifferDlg::Sniffer_updateTree(int index)
{
	POSITION localpos;
	CString str;
	int i;

	this->m_treeCtrl.DeleteAllItems();

	localpos = this->m_localDataList.FindIndex(index);
	struct datapkt* local_data = (struct datapkt*)(this->m_localDataList.GetAt(localpos));

	HTREEITEM root = this->m_treeCtrl.GetRootItem();
	str.Format(_T("接收到的第%d个数据包"), index + 1);
	HTREEITEM data = this->m_treeCtrl.InsertItem(str, root);

	/*处理帧数据*/
	HTREEITEM frame = this->m_treeCtrl.InsertItem(_T("链路层数据"), data);
	//源MAC
	str.Format(_T("源MAC："));
	for (i = 0; i < 6; i++)
	{
		if (i <= 4)
			str.AppendFormat(_T("%02x-"), local_data->ethh->src[i]);
		else
			str.AppendFormat(_T("%02x"), local_data->ethh->src[i]);
	}
	this->m_treeCtrl.InsertItem(str, frame);
	//目的MAC
	str.Format(_T("目的MAC："));
	for (i = 0; i < 6; i++)
	{
		if (i <= 4)
			str.AppendFormat(_T("%02x-"), local_data->ethh->dest[i]);
		else
			str.AppendFormat(_T("%02x"), local_data->ethh->dest[i]);
	}
	this->m_treeCtrl.InsertItem(str, frame);
	//类型
	str.Format(_T("类型：0x%02x"), local_data->ethh->type);
	this->m_treeCtrl.InsertItem(str, frame);

	/*处理IP、ARP、IPv6数据包*/
	if (0x0806 == local_data->ethh->type)							//ARP
	{
		HTREEITEM arp = this->m_treeCtrl.InsertItem(_T("ARP协议头"), data);
		str.Format(_T("硬件类型：%d"), local_data->arph->ar_hrd);
		this->m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("协议类型：0x%02x"), local_data->arph->ar_pro);
		this->m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("硬件地址长度：%d"), local_data->arph->ar_hln);
		this->m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("协议地址长度：%d"), local_data->arph->ar_pln);
		this->m_treeCtrl.InsertItem(str, arp);
		str.Format(_T("操作码：%d"), local_data->arph->ar_op);
		this->m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("发送方MAC："));
		for (i = 0; i < 6; i++)
		{
			if (i <= 4)
				str.AppendFormat(_T("%02x-"), local_data->arph->ar_srcmac[i]);
			else
				str.AppendFormat(_T("%02x"), local_data->arph->ar_srcmac[i]);
		}
		this->m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("发送方IP："), local_data->arph->ar_hln);
		for (i = 0; i < 4; i++)
		{
			if (i <= 2)
				str.AppendFormat(_T("%d."), local_data->arph->ar_srcip[i]);
			else
				str.AppendFormat(_T("%d"), local_data->arph->ar_srcip[i]);
		}
		this->m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("接收方MAC："), local_data->arph->ar_hln);
		for (i = 0; i < 6; i++)
		{
			if (i <= 4)
				str.AppendFormat(_T("%02x-"), local_data->arph->ar_destmac[i]);
			else
				str.AppendFormat(_T("%02x"), local_data->arph->ar_destmac[i]);
		}
		this->m_treeCtrl.InsertItem(str, arp);

		str.Format(_T("接收方IP："), local_data->arph->ar_hln);
		for (i = 0; i < 4; i++)
		{
			if (i <= 2)
				str.AppendFormat(_T("%d."), local_data->arph->ar_destip[i]);
			else
				str.AppendFormat(_T("%d"), local_data->arph->ar_destip[i]);
		}
		this->m_treeCtrl.InsertItem(str, arp);

	}
	else if (0x0800 == local_data->ethh->type) {					//IP

		HTREEITEM ip = this->m_treeCtrl.InsertItem(_T("IP协议头"), data);

		str.Format(_T("版本：%d"), local_data->iph->version);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("IP头长：%d"), local_data->iph->ihl);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("服务类型：%d"), local_data->iph->tos);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("总长度：%d"), local_data->iph->tlen);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("标识：0x%02x"), local_data->iph->id);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("段偏移：%d"), local_data->iph->frag_off);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("生存期：%d"), local_data->iph->ttl);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("协议：%d"), local_data->iph->proto);
		this->m_treeCtrl.InsertItem(str, ip);
		str.Format(_T("头部校验和：0x%02x"), local_data->iph->check);
		this->m_treeCtrl.InsertItem(str, ip);

		str.Format(_T("源IP："));
		struct in_addr in;
		in.S_un.S_addr = local_data->iph->saddr;
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_treeCtrl.InsertItem(str, ip);

		str.Format(_T("目的IP："));
		in.S_un.S_addr = local_data->iph->daddr;
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_treeCtrl.InsertItem(str, ip);

		/*处理传输层ICMP、UDP、TCP*/
		if (1 == local_data->iph->proto)							//ICMP
		{
			HTREEITEM icmp = this->m_treeCtrl.InsertItem(_T("ICMP协议头"), data);

			str.Format(_T("类型:%d"), local_data->icmph->type);
			this->m_treeCtrl.InsertItem(str, icmp);
			str.Format(_T("代码:%d"), local_data->icmph->code);
			this->m_treeCtrl.InsertItem(str, icmp);
			str.Format(_T("序号:%d"), local_data->icmph->seq);
			this->m_treeCtrl.InsertItem(str, icmp);
			str.Format(_T("校验和:%d"), local_data->icmph->chksum);
			this->m_treeCtrl.InsertItem(str, icmp);

		}
		else if (6 == local_data->iph->proto) {				//TCP

			HTREEITEM tcp = this->m_treeCtrl.InsertItem(_T("TCP协议头"), data);

			str.Format(_T("  源端口:%d"), local_data->tcph->sport);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  目的端口:%d"), local_data->tcph->dport);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  序列号:0x%02x"), local_data->tcph->seq);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  确认号:%d"), local_data->tcph->ack_seq);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  头部长度:%d"), local_data->tcph->doff);

			HTREEITEM flag = this->m_treeCtrl.InsertItem(_T(" +标志位"), tcp);

			str.Format(_T("cwr %d"), local_data->tcph->cwr);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("ece %d"), local_data->tcph->ece);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("urg %d"), local_data->tcph->urg);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("ack %d"), local_data->tcph->ack);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("psh %d"), local_data->tcph->psh);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("rst %d"), local_data->tcph->rst);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("syn %d"), local_data->tcph->syn);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("fin %d"), local_data->tcph->fin);
			this->m_treeCtrl.InsertItem(str, flag);

			str.Format(_T("  紧急指针:%d"), local_data->tcph->urg_ptr);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  校验和:0x%02x"), local_data->tcph->check);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  选项:%d"), local_data->tcph->opt);
			this->m_treeCtrl.InsertItem(str, tcp);
		}
		else if (17 == local_data->iph->proto) {				//UDP
			HTREEITEM udp = this->m_treeCtrl.InsertItem(_T("UDP协议头"), data);

			str.Format(_T("源端口:%d"), local_data->udph->sport);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("目的端口:%d"), local_data->udph->dport);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("总长度:%d"), local_data->udph->len);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("校验和:0x%02x"), local_data->udph->check);
			this->m_treeCtrl.InsertItem(str, udp);
		}
	}
	else if (0x86dd == local_data->ethh->type) {		//IPv6
		HTREEITEM ip6 = this->m_treeCtrl.InsertItem(_T("IPv6协议头"), data);

		//
		str.Format(_T("版本:%d"), local_data->iph6->flowtype);
		this->m_treeCtrl.InsertItem(str, ip6);
		str.Format(_T("流类型:%d"), local_data->iph6->version);
		this->m_treeCtrl.InsertItem(str, ip6);
		///
		str.Format(_T("流标签:%d"), local_data->iph6->flowid);
		this->m_treeCtrl.InsertItem(str, ip6);
		str.Format(_T("有效载荷长度:%d"), local_data->iph6->plen);
		this->m_treeCtrl.InsertItem(str, ip6);
		str.Format(_T("下一个首部:0x%02x"), local_data->iph6->nh);
		this->m_treeCtrl.InsertItem(str, ip6);
		str.Format(_T("跳限制:%d"), local_data->iph6->hlim);
		this->m_treeCtrl.InsertItem(str, ip6);

		str.Format(_T("源地址:"));
		int n;
		for (n = 0; n < 8; n++)
		{
			if (n <= 6)
				str.AppendFormat(_T("%02x:"), local_data->iph6->saddr[n]);
			else
				str.AppendFormat(_T("%02x"), local_data->iph6->saddr[n]);
		}
		this->m_treeCtrl.InsertItem(str, ip6);

		str.Format(_T("目的地址:"));
		for (n = 0; n < 8; n++)
		{
			if (n <= 6)
				str.AppendFormat(_T("%02x:"), local_data->iph6->saddr[n]);
			else
				str.AppendFormat(_T("%02x"), local_data->iph6->saddr[n]);
		}
		this->m_treeCtrl.InsertItem(str, ip6);

		/*处理传输层ICMPv6、UDP、TCP*/
		if (0x3a == local_data->iph6->nh)							//ICMPv6
		{
			HTREEITEM icmp6 = this->m_treeCtrl.InsertItem(_T("ICMPv6协议头"), data);

			str.Format(_T("类型:%d"), local_data->icmph6->type);
			this->m_treeCtrl.InsertItem(str, icmp6);
			str.Format(_T("代码:%d"), local_data->icmph6->code);
			this->m_treeCtrl.InsertItem(str, icmp6);
			str.Format(_T("序号:%d"), local_data->icmph6->seq);
			this->m_treeCtrl.InsertItem(str, icmp6);
			str.Format(_T("校验和:%d"), local_data->icmph6->chksum);
			this->m_treeCtrl.InsertItem(str, icmp6);
			str.Format(_T("选项-类型:%d"), local_data->icmph6->op_type);
			this->m_treeCtrl.InsertItem(str, icmp6);
			str.Format(_T("选项-长度%d"), local_data->icmph6->op_len);
			this->m_treeCtrl.InsertItem(str, icmp6);
			str.Format(_T("选项-链路层地址:"));
			int i;
			for (i = 0; i < 6; i++)
			{
				if (i <= 4)
					str.AppendFormat(_T("%02x-"), local_data->icmph6->op_ethaddr[i]);
				else
					str.AppendFormat(_T("%02x"), local_data->icmph6->op_ethaddr[i]);
			}
			this->m_treeCtrl.InsertItem(str, icmp6);

		}
		else if (0x06 == local_data->iph6->nh) {				//TCP

			HTREEITEM tcp = this->m_treeCtrl.InsertItem(_T("TCP协议头"), data);

			str.Format(_T("  源端口:%d"), local_data->tcph->sport);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  目的端口:%d"), local_data->tcph->dport);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  序列号:0x%02x"), local_data->tcph->seq);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  确认号:%d"), local_data->tcph->ack_seq);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  头部长度:%d"), local_data->tcph->doff);

			HTREEITEM flag = this->m_treeCtrl.InsertItem(_T("标志位"), tcp);

			str.Format(_T("cwr %d"), local_data->tcph->cwr);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("ece %d"), local_data->tcph->ece);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("urg %d"), local_data->tcph->urg);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("ack %d"), local_data->tcph->ack);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("psh %d"), local_data->tcph->psh);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("rst %d"), local_data->tcph->rst);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("syn %d"), local_data->tcph->syn);
			this->m_treeCtrl.InsertItem(str, flag);
			str.Format(_T("fin %d"), local_data->tcph->fin);
			this->m_treeCtrl.InsertItem(str, flag);

			str.Format(_T("  紧急指针:%d"), local_data->tcph->urg_ptr);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  校验和:0x%02x"), local_data->tcph->check);
			this->m_treeCtrl.InsertItem(str, tcp);
			str.Format(_T("  选项:%d"), local_data->tcph->opt);
			this->m_treeCtrl.InsertItem(str, tcp);
		}
		else if (0x11 == local_data->iph6->nh) {				//UDP
			HTREEITEM udp = this->m_treeCtrl.InsertItem(_T("UDP协议头"), data);

			str.Format(_T("源端口:%d"), local_data->udph->sport);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("目的端口:%d"), local_data->udph->dport);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("总长度:%d"), local_data->udph->len);
			this->m_treeCtrl.InsertItem(str, udp);
			str.Format(_T("校验和:0x%02x"), local_data->udph->check);
			this->m_treeCtrl.InsertItem(str, udp);
		}
	}

	return 1;
}
//结束按钮
void CSnifferDlg::OnBnClickedButton3()
{
	// TODO: 在此添加控件通知处理程序代码
	if (NULL == this->m_ThreadHandle)
		return;
	//终止线程
	if (TerminateThread(this->m_ThreadHandle, -1) == 0)
	{
		MessageBox(_T("关闭线程错误，请稍后重试"));
		return;
	}
	this->m_ThreadHandle = NULL;
	this->Start_Button.EnableWindow(TRUE);
	this->End_Button.EnableWindow(FALSE);
	this->Save_Button.EnableWindow(TRUE);
}
//开始按钮
void CSnifferDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
	if (MessageBox(_T("保存数据？"), _T("warning"), MB_YESNO) == IDYES)
	{
		this->Sniffer_saveFile();
	}
	this->npkt = 1;//重新计数数据包数目
	this->m_localDataList.RemoveAll();
	this->m_netDataList.RemoveAll();//清除数据包
	memset(&(this->npacket), 0, sizeof(struct pktcount));//为数据包分配内存
	this->Sniffer_updatePacket();//调用数据包更新函数
	//开始抓包
	if (this->Sniffer_startCap() < 0)
		return;
	//删除以前的数据
	this->m_listCtrl.DeleteAllItems();
	this->m_treeCtrl.DeleteAllItems();
	this->m_edit.SetWindowTextW(_T(""));
	this->Start_Button.EnableWindow(FALSE);
	this->End_Button.EnableWindow(TRUE);
	this->Send_Button.EnableWindow(TRUE);
	this->m_ComboBoxPk.EnableWindow(TRUE);
	this->Save_Button.EnableWindow(FALSE);
}
//发送按钮
void CSnifferDlg::OnBnClickedButton6()
{
	
	if (Sniffer_sendPacket() < 0)
	{

		MessageBox(_T("数据包发送失败"));
	}
	else
	{
		MessageBox(_T("数据包发送成功"));
	}
}

void CSnifferDlg::OnNMDblclkList2(NMHDR* pNMHDR, LRESULT* pResult)
{
	/*LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码
	*pResult = 0;
	//如果用户需要改写数据包
	int nItem;
	pcap_t* fp;
	int len1,len2;
	int x ;
	libnet_t *lib_net=NULL;
	libnet_ptag_t lib_t;
	char err_buf[100] = "";
	const uint8_t msg[1000] = "";
	char* send_msg = "";
	int lens = 0;
	//struct pcap_pkthdr* header;						    //数据包头
	const u_char* fake_pkt= NULL;                     //数据包数据
	if (MessageBox(_T("是否要改写数据包？"), _T("warning"), MB_YESNO) == IDYES)
	{
		/*
		char send_msg[1000] = "";
		char err_buf[100] = "";
		libnet_t* lib_net = NULL;
		int lens = 0;
		libnet_ptag_t lib_t = 0;
		unsigned char src_mac[6] = { 0x00,0x0c,0x29,0x97,0xc7,0xc1 };//发送者网卡地址00:0c:29:97:c7:c1  
		unsigned char dst_mac[6] = { 0x74,0x27,0xea,0xb5,0xff,0xd8 };//接收者网卡地址‎74-27-EA-B5-FF-D8  
		char* src_ip_str = "192.168.31.163"; //源主机IP地址  
		char* dst_ip_str = "192.168.31.248"; //目的主机IP地址  
		unsigned long src_ip, dst_ip = 0;

		lens = sprintf(send_msg, "%s", "this is for the udp test");

		lib_net = libnet_init(LIBNET_RAW4, "eth0", err_buf);    //初始化  
		if (NULL == lib_net)
		{
			MessageBox(_T("初始化失败"));
		}
		src_ip = libnet_name2addr4(lib_net, src_ip_str, LIBNET_RESOLVE);  //将字符串类型的ip转换为顺序网络字节流  
		dst_ip = libnet_name2addr4(lib_net, dst_ip_str, LIBNET_RESOLVE);

		lib_t = libnet_build_udp(   //构造udp数据包  
			8080,
			8080,
			8 + lens,
			0,
			(uint8_t*)send_msg,
			lens,
			lib_net,
			0
		);

		lib_t = libnet_build_ipv4(  //构造ip数据包  
			20 + 8 + lens,
			0,
			500,
			0,
			10,
			17,
			0,
			src_ip,
			dst_ip,
			NULL,
			0,
			lib_net,
			0
		);

		lib_t = libnet_build_ethernet(  //构造以太网数据包  
			(u_int8_t*)dst_mac,
			(u_int8_t*)src_mac,
			0x800, // 或者，ETHERTYPE_IP  
			NULL,
			0,
			lib_net,
			0
		);
		int res = 0;
		res = libnet_write(lib_net);    //发送数据包  
		if (-1 == res)
		{
			MessageBox(_T("数据包发送失败"));
		}

		libnet_destroy(lib_net);    //销毁资源  
		MessageBox(_T("数据包发送成功"));*/
	
}








void CAboutDlg::OnBnClickedButton3()
{
	// TODO: 在此添加控件通知处理程序代码
}
void CAboutDlg::OnBnClickedButton2()
{
	// TODO: 在此添加控件通知处理程序代码
}



void CSnifferDlg::OnEnChangeEdit2()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


void CSnifferDlg::OnEnChangeEdit7()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


void CSnifferDlg::OnEnChangeCombo3()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


void CSnifferDlg::OnCbnSelchangeCombo4()
{
	// TODO: 在此添加控件通知处理程序代码
}


void CAboutDlg::OnBnClickedButton1()
{
	// TODO: 在此添加控件通知处理程序代码
}


void CSnifferDlg::OnCbnSelchangeCombo2()
{
	// TODO: 在此添加控件通知处理程序代码
}


void CSnifferDlg::OnEnChangeEdit4()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


void CSnifferDlg::OnEnChangeEdit3()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


void CSnifferDlg::OnEnChangeEdit5()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


void CSnifferDlg::OnEnChangeEdit6()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}


void CSnifferDlg::OnEnChangeEdit9()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}

void CSnifferDlg::OnBnClickedButton5()
{
	// TODO: 在此添加控件通知处理程序代码

}


void CSnifferDlg::OnEnChangeEdit10()
{
	// TODO:  如果该控件是 RICHEDIT 控件，它将不
	// 发送此通知，除非重写 CDialogEx::OnInitDialog()
	// 函数并调用 CRichEditCtrl().SetEventMask()，
	// 同时将 ENM_CHANGE 标志“或”运算到掩码中。

	// TODO:  在此添加控件通知处理程序代码
}




