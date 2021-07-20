
// SnifferDlg.h: 头文件
//

#pragma once
#include "pch.h"
#include "framework.h"
#include "Sniffer.h"
#include "SnifferDlg.h"
#include"Protocol.h"
#include"pcap.h"
// CSnifferDlg 对话框
class CSnifferDlg : public CDialogEx
{
// 构造
public:
	CSnifferDlg(CWnd* pParent = nullptr);	// 标准构造函数
	/*功能函数*/
	int Sniffer_initCap();//初始化
	int Sniffer_startCap();//开始捕获
	int Sniffer_saveFile();//保存数据
	int Sniffer_readFile(CString path);//读取数据
	int Sniffer_updatePacket();//更新包数据
	int Sniffer_sendPacket();//发送数据包
	int Sniffer_updateInfo(int index);//更新信息
	int Sniffer_updateTree(int index);//更新树形结构
	//int Sniffer_changePacket();//改写数据包
	/*数据部分*/
public:
	pcap_if_t* alldevs;//显示网卡
	pcap_if_t* d;
	int inum;//网卡标志
	int i = 0;
	pcap_t* adhandle;                       //用于保存数据包
	struct pktcount npacket;				//各类数据包计数
	char errbuf[PCAP_ERRBUF_SIZE];          //错误处理
	CPtrList m_localDataList;				//保存被本地化后的数据包
	CPtrList m_netDataList;					//保存从网络中直接获取的数据包
	char filename[256];
	char filepath[512];
	u_int BYTE=0;                               //记录字节数
	pcap_dumper_t* dumpfile;
	HANDLE m_ThreadHandle;                  //创建线程
	CPtrList m_pktList;					    //捕获包所存放的链表
	int npkt;
// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_SNIFFER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnLvnItemchangedList2(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnEnChangeEdit1();
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton4();
	afx_msg void OnEnChangeTcp();
	CButton Start_Button;
	CButton End_Button;
	afx_msg void OnCbnSelchangeCombo1();
	CTreeCtrl m_treeCtrl;
	CListCtrl m_listCtrl;
	CComboBox m_ComboBox;
	CButton Save_Button;
	CButton Load_Button;
	CComboBox m_ComboBoxRule;
	afx_msg void OnBnClickedButton2();
	afx_msg void OnBnClickedButton3();
	afx_msg void OnEnChangeEdit2();
	afx_msg void OnEnChangeEdit7();
	CEdit m_editNTcp;
	CEdit m_editNHttp;
	CEdit m_editNIpv6;
	CEdit m_editNUdp;
	CEdit m_editNArp;
	CEdit m_editNIpv4;
	CEdit m_editNIcmp;
	CEdit m_edit;
	afx_msg void OnEnChangeCombo3();
	afx_msg void OnCbnSelchangeCombo4();
	afx_msg void OnCbnSelchangeCombo2();
	afx_msg void OnEnChangeEdit4();
	afx_msg void OnEnChangeEdit3();
	afx_msg void OnEnChangeEdit5();
	afx_msg void OnEnChangeEdit6();
	CEdit m_editNOther;//用于统计其他包
	afx_msg void OnEnChangeEdit9();
	CEdit m_editNSum;//用于统计包的总数
	afx_msg void OnBnClickedButton5();
	CEdit m_editNflow;//用于统计流量
	afx_msg void OnEnChangeEdit10();
	afx_msg void OnNMDblclkList2(NMHDR* pNMHDR, LRESULT* pResult);
	// 发送数据包按钮
	CButton Send_Button;
	afx_msg void OnBnClickedButton6();
	CComboBox m_ComboBoxPk;
};
