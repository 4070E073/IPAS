重要
http://newsletter.ascc.sinica.edu.tw/news/read_news.php?nid=1917
新聞
https://www.ithome.com.tw/news/118411
次要
https://leoyeh.me/2017/11/24/%E8%B3%87%E5%AE%89%E7%AE%A1%E7%90%86-OWASP-Top-10-1/

# 2017 OWASP TOP 10 
A1-Injection（注入攻擊）
A2-無效身分認證（Broken Authentication）
A3-敏感資料外洩（Sensitive Data Exposure）
A4-XML外部處理器漏洞(XML External Entity，XEE)
A5-無效的存取控管 (Broken Access Control)
A6-不安全的組態設定 (Security Misconfiguration)
A7-跨站攻擊 (Cross-Site Script，XSS)
A8-不安全的反序列化漏洞 (Insecure Deserialization)
A9-使用已有漏洞的元件 (Using Components with Known Vulnerabilities)
A10-紀錄與監控不足風險(Insufficient Logging & Monitoring)

1.Injection（注入攻擊）
  網站應用程式執行來自外部包括資料庫在內的惡意指令，SQL Injection與Command Injection等攻擊包括在內。
  因為駭客必須猜測管理者所撰寫的方式，因此又稱「駭客的填空遊戲」。
  
  //詳細解釋在第一個網站
  
  簡述駭客攻擊流程：

    1.找出未保護變數，作為注入點
    2.猜測完整Command並嘗試插入
    3.推測欄位數、Table名稱、SQL版本等資訊
    4.完整插入完成攻擊程序 
    
　防護建議：

    1.使用Prepared Statements，例如Java PreparedStatement()，.NET SqlCommand(), OleDbCommand()，PHP PDO bindParam()
    2.使用Stored Procedures
    3.嚴密的檢查所有輸入值
    4.使用過濾字串函數過濾非法的字元，例如mysql_real_escape_string、addslashes
    5.控管錯誤訊息只有管理者可以閱讀
    6.控管資料庫及網站使用者帳號權限為何








