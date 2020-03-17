// Dialg_Def.cpp : 实现文件
//

#include "stdafx.h"
#include "mqtt_client.h"
#include "Dialg_Def.h"
#include "afxdialogex.h"
#include "mqtt_clientDlg.h"
#include "deflate.h"


int check_in_hex =1;
int check_out_hex =1;


int comproess_mod = 1;// 0 表示解压，1表示压缩

// CDialg_Def 对话框

IMPLEMENT_DYNAMIC(CDialg_Def, CDialog)

CDialg_Def::CDialg_Def(CWnd* pParent /*=NULL*/)
	: CDialog(CDialg_Def::IDD, pParent)
	, m_edit_in(_T(""))
	, m_edit_out(_T(""))
	, m_check_in(TRUE)
	, m_check_out(TRUE)
	, m_text_any(_T(""))
{

}

CDialg_Def::~CDialg_Def()
{
}

void CDialg_Def::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_IN, m_edit_in);
	DDX_Text(pDX, IDC_EDIT_OUT, m_edit_out);
	DDX_Check(pDX, IDC_CHECK_IN_HEX, m_check_in);
	DDX_Control(pDX, IDC_CHECK_IN_HEX, c_check_in);
	DDX_Check(pDX, IDC_CHECK_OUT_HEX, m_check_out);
	DDX_Control(pDX, IDC_CHECK_OUT_HEX, c_check_out);
	DDX_Control(pDX, IDC_BUTTON_COM, c_button_com);
	DDX_Text(pDX, IDC_STATIC_ANY, m_text_any);
}

//	ON_BN_CLICKED(IDC_BUTTON_GO, &CDialg_Def::OnBnClickedButton2)
BEGIN_MESSAGE_MAP(CDialg_Def, CDialog)
	ON_BN_CLICKED(IDOK, &CDialg_Def::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CDialg_Def::OnBnClickedCancel)
	ON_BN_CLICKED(IDC_CHECK_IN_HEX, &CDialg_Def::OnBnClickedCheckInHex)
	ON_BN_CLICKED(IDC_CHECK_OUT_HEX, &CDialg_Def::OnBnClickedCheckOutHex)
	ON_BN_CLICKED(IDC_BUTTON_GO, &CDialg_Def::OnBnClickedButtonGo)
	ON_BN_CLICKED(IDC_BUTTON_COM, &CDialg_Def::OnBnClickedButtonCom)
END_MESSAGE_MAP()


// CDialg_Def 消息处理程序

void CDialg_Def::OnBnClickedOk()
{
	// TODO:  在此添加控件通知处理程序代码
	MessageBox(L"作者：一路向东");
}


void CDialg_Def::OnBnClickedCancel()
{
	// TODO:  在此添加控件通知处理程序代码
	CDialog::OnCancel();
}


void CDialg_Def::OnBnClickedCheckInHex()
{
	// TODO:  在此添加控件通知处理程序代码
	if (c_check_in.GetCheck())
	{
		check_in_hex = 1;
	}
	else
	{
		check_in_hex = 0;
	}


}


void CDialg_Def::OnBnClickedCheckOutHex()
{
	// TODO:  在此添加控件通知处理程序代码
	if (c_check_out.GetCheck())
	{
		check_out_hex = 1;
	}
	else
	{
		check_out_hex = 0;
	}

}


void CDialg_Def::OnBnClickedButtonGo()
{
	// TODO:  在此添加控件通知处理程序代码
    unsigned char data_str[10*1024]="";
	int           data_str_length=0;
    unsigned char data_in[10*1024]="";// 最多10K
	int           data_in_length = 0;
	unsigned char data_out[10*1024]="";// 最多10K
    int           data_out_length=0;
	int           hex_length=0;
	int res = 0;


	unsigned char inflate_buff[10 * 1024] = "";
	int           inflate_len = sizeof(inflate_buff);



	TCHAR out_str[10 * 1024] = L"";
	unsigned char out_hex[10 * 1024] = "";

    UpdateData(true);

	data_str_length = m_edit_in.GetLength();
	wcharTochar(m_edit_in, (char *)data_str, data_str_length);

	if (comproess_mod == 1)
	{
		 
		// 如果是压缩模式
		
       if(check_in_hex==1)
       	{
       	
		   // 需要将字符转成16进制数据
		   hex_length = str_to_hex((char *)data_str, data_in);
		   if (hex_length == -1)
		   {
			   MessageBox(L"存在非法字符");
			   UpdateData(false);
			   return;
		   }
		   data_in_length = hex_length;
       	}
	   else
	   {
		   memcpy(data_in, data_str, data_str_length);
		   data_in_length = data_str_length;
	   }

	   // 开始压缩
	   data_out_length = sizeof(data_out);
	   res = compress(data_out, (uLongf *)&data_out_length, data_in, data_in_length);


	   if (data_in_length == 0)
	   {

		   m_text_any.Format(L"输出/输入=%d/%d,压缩率:1000+%%----，不好意思，软件发生了除0错误。（开个玩笑，拜托，你好歹输点什么吧）", data_out_length, data_in_length);
	   }
	   else
	   {
		   m_text_any.Format(L"输出/输入=%d/%d,压缩率：%f%%,", data_out_length, data_in_length, 100.0*((float)data_out_length / (float)data_in_length));

	   }





	   if (check_out_hex == 1)
	   {
		   hex_to_ascii((char *)out_hex, data_out, data_out_length);
		   swprintf(out_str, L"%S", out_hex);
	   }
	   else
	   {
		   swprintf(out_str, L"%S", data_out);
	   }
	  // swprintf(Paylaod_L, L"%S", hex_str);

	 


	   printf("compress res :%d,length:%d \r\n", res, data_out_length);
	   // 压缩之后，试一下解压看是不是成功的
	   res = uncompress(inflate_buff, (uLongf *)&inflate_len, data_out, data_out_length);
	   printf("uncompress :%d,length:%d \r\n", res, inflate_len);
	   
	   for (int j = 0; j<inflate_len; j++)
	   {
		   printf("%02x", inflate_buff[j]);

	   }
	   printf("\r\n");

	   if (res == 0 || res == 1)
	   {
		   m_edit_out.Format(out_str);
	   }
	   else
	   {
		   MessageBox(L"压缩失败");	UpdateData(false);
		   return;
	   }




	}
	else
	{
		// 如果是解压模式
		if (check_in_hex == 1)
		{

			// 需要将字符转成16进制数据
			hex_length = str_to_hex((char *)data_str, data_in);
			if (hex_length == -1)
			{
				MessageBox(L"存在非法字符");
				UpdateData(false);
				return;
			}
			data_in_length = hex_length;
		}
		else
		{
			memcpy(data_in, data_str, data_str_length);
			data_in_length = data_str_length;
		}
		// 开始解压
		data_out_length = sizeof(data_out);
		//res = compress(data_out, (uLongf *)&data_out_length, data_in, data_in_length);
		res = uncompress(data_out, (uLongf *)&data_out_length, data_in, data_in_length);
		printf("uncompress res :%d,length :%d \r\n", res, data_out_length);


		if (res == 0 || res == 1)
		{
			//m_edit_out.Format(out_str);
		}
		else
		{
			MessageBox(L"解压失败");
			UpdateData(false);
			return;
		}


		if (data_out_length>0)
		{
			m_text_any.Format(L"输入/输出=%d/%d,源数据的压缩率：%f%%,", data_in_length,data_out_length , 100.0*((float)data_in_length / (float)data_out_length));

		}
		else
		{
			m_text_any.Format(L"输出为0，输入为:%d", data_in_length);
		}

		if (check_out_hex == 1)
		{
			hex_to_ascii((char *)out_hex, data_out, data_out_length);
			swprintf(out_str, L"%S", out_hex);
		}
		else
		{
			swprintf(out_str, L"%S", data_out);
		}
		// swprintf(Paylaod_L, L"%S", hex_str);

		  m_edit_out.Format(out_str);













	}








	UpdateData(false);


}


/*
void CDialg_Def::OnBnClickedButton2()
{
	// TODO:  在此添加控件通知处理程序代码
	printf("OnBnClickedButtonCom:%d \r\n", comproess_mod);
	UpdateData(true);
	printf("OnBnClickedButtonCom:%d \r\n", comproess_mod);
	if (comproess_mod == 1)
	{
		comproess_mod = 0;
		c_button_com.SetWindowTextW(L"解压（点击切换到压缩模式）");
	}
	else
	{
		comproess_mod = 1;
		c_button_com.SetWindowTextW(L"压缩（点击切换到解压模式）");
	}

	c_check_in.SetCheck(true);
	c_check_out.SetCheck(true);
	m_check_in = 1;
	m_check_out = 1;

	check_in_hex = 1;
	check_out_hex = 1;
	UpdateData(true);
	

}
*/


void CDialg_Def::OnBnClickedButtonCom()
{
	// TODO:  在此添加控件通知处理程序代码
	UpdateData(true);
	printf("OnBnClickedButtonCom:%d \r\n", comproess_mod);
	if (comproess_mod == 1)
	{
		comproess_mod = 0;
		c_button_com.SetWindowTextW(L"解压（点击切换到压缩模式）");
	}
	else
	{
		comproess_mod = 1;
		c_button_com.SetWindowTextW(L"压缩（点击切换到解压模式）");
	}

	m_check_in = 1;
	m_check_out = 1;


	UpdateData(true);
}
