#pragma once
#include "afxwin.h"


// CDialg_Def 对话框

class CDialg_Def : public CDialog
{
	DECLARE_DYNAMIC(CDialg_Def)

public:
	CDialg_Def(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CDialg_Def();

// 对话框数据
	enum { IDD = IDD_DIALOG_DEF };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	CString m_edit_in;
	CString m_edit_out;
	afx_msg void OnBnClickedCheckInHex();
	afx_msg void OnBnClickedCheckOutHex();
	afx_msg void OnBnClickedButtonGo();
	afx_msg void OnBnClickedButton2();
	BOOL m_check_in;
	CButton c_check_in;
	BOOL m_check_out;
	CButton c_check_out;
	CButton c_button_com;
	afx_msg void OnBnClickedButtonCom();
	CString m_text_any;
};
