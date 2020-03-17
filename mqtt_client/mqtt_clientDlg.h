
// mqtt_clientDlg.h : 头文件
//

#pragma once
#include "afxwin.h"


// Cmqtt_clientDlg 对话框
class Cmqtt_clientDlg : public CDialogEx
{
// 构造
public:
	Cmqtt_clientDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_MQTT_CLIENT_DIALOG };

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
	afx_msg void OnBnClickedButtonMqConnect();
	
	 static void FEMQTT_MAIN(LPVOID lpv);
//	CString m_edit_url;
//	CString m_edit_user;
//	DWORD m_edit_port;
//	CString m_edit_pass;
//	DWORD m_edit_kalive;
//	CString m_edit_deviceid;
//	DWORD m_edit_port2;
	CString m_edit_url;
	CString m_edit_user;
	CString m_edit_pass;
//	CString m_edit_kalive;
	CString m_edit_deviceid;
	DWORD m_edit_kalive;
	DWORD m_edit_port;
	CString m_text_status;
	CEdit c_edit_port;
	int m_combo_sub_q;
	int m_combo_pub_q;
	CString m_combo_sub_topic;
	CComboBox c_combo_sub_topic;
	afx_msg void OnBnClickedButtonSub();
	afx_msg void OnBnClickedButtonUnsub();
	CString m_edit_recv_topic;
	CString m_edit_recv_payload;
	afx_msg void OnBnClickedCheckPubHex();
	afx_msg void OnBnClickedCheckRecvHex();
	afx_msg void OnBnClickedCheckPubDef();
	afx_msg void OnBnClickedCheckRecvSave();
	CButton c_check_recv_hex;
	CButton c_check_recv_save;
	afx_msg void OnBnClickedButtonPub();
	CString m_edit_pub_topic;
	CString m_edit_pub_payload;
//	CButton c_check_pub_hex;
	CButton c_check_pub_hex;
	afx_msg void OnBnClickedButtonDef();
	afx_msg void OnBnClickedCheckSsl();
	CButton c_check_ssl;
	CString m_text_ssl;
	CButton c_button_ad;
	afx_msg void OnBnClickedCheckAd();
	CButton c_check_ad;
	afx_msg void OnBnClickedButtonAd();
	afx_msg void OnBnClickedButtonTell();
//	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
//	afx_msg void OnNcPaint();
};



void wcharTochar(const wchar_t *wchar, char *chr, int length);  
void hex_to_ascii(char *asciistr,unsigned char *hexstr,int hex_length);
int check_ascii_is_hex(char a);
unsigned char ascii_to_hex(char a1,char a2);
int str_to_hex(char *asciistr,unsigned char *hexstr);



