重要
http://newsletter.ascc.sinica.edu.tw/news/read_news.php?nid=1917

新聞
https://www.ithome.com.tw/news/118411

次要
https://leoyeh.me/2017/11/24/%E8%B3%87%E5%AE%89%E7%AE%A1%E7%90%86-OWASP-Top-10-1/

# 2017 OWASP TOP 10 
```
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
```

# A1 - Injection（注入攻擊）
  網站應用程式執行來自外部包括資料庫在內的惡意指令，SQL Injection與Command Injection等攻擊包括在內。
  因為駭客必須猜測管理者所撰寫的方式，因此又稱「駭客的填空遊戲」。
  
  舉例來說，原本管理者設計的登入頁面資料庫語法如下： 
 
$str = "SELECT * FROM Users WHERE Username='“.$user."' and 
Password=‘”.$pass."'“; 
 
　如果說$user以及$pass變數沒有做保護，駭客只要輸入「’ or ‘‘=’」字串，就會變成以下： 
 
$str = “SELECT * FROM Users WHERE Username='' or ''='' and Password= '' or 
‘’=‘’”; 
 
　如此一來，這個SQL語法就會規避驗證手續，直接顯示資料。
  
  ### 簡述駭客攻擊流程：
   ```
    1.找出未保護變數，作為注入點
    2.猜測完整Command並嘗試插入
    3.推測欄位數、Table名稱、SQL版本等資訊
    4.完整插入完成攻擊程序 
   ```
   
### 防護建議：
  
   > * 使用Prepared Statements，例如Java PreparedStatement()，.NET SqlCommand(), OleDbCommand()，PHP PDO bindParam()
   > * 使用Stored Procedures
   > * 嚴密的檢查所有輸入值
   > * 使用過濾字串函數過濾非法的字元，例如mysql_real_escape_string、addslashes
   > * 控管錯誤訊息只有管理者可以閱讀
   > * 控管資料庫及網站使用者帳號權限為何
  
  
  
 # A2 – Cross Site Scripting ( XSS )（跨站腳本攻擊） 
 
　網站應用程式直接將來自使用者的執行請求送回瀏覽器執行，使得攻擊者可擷取使用者的Cookie或Session資料而能假冒直接登入為合法使用者。  
　此為目前受災最廣的攻擊。簡稱XSS攻擊。
 
### 攻擊流程如下：
```
1.受害者登入一個網站
2.從Server端取得Cookie
3.但是Server端上有著XSS攻擊，使受害者將Cookie回傳至Bad Server
4.攻擊者從自己架設的Bad Server上取得受害者Cookie
5.攻擊者取得控制使用受害者的身分
```

### 防護建議：

> * 檢查頁面輸入數值
> * 輸出頁面做Encoding檢查
> * 使用白名單機制過濾，而不單只是黑名單
> * PHP使用htmlentities過濾字串
> * .NET使用Microsoft Anti-XSS Library
> * OWASP Cross Site Scripting Prevention Cheat Sheet
> * 各種XSS攻擊的Pattern參考 



# A3 – Broken Authentication and Session Management（身分驗證功能缺失） 
 
　網站應用程式中自行撰寫的身分驗證相關功能有缺陷。例如，登入時無加密、SESSION無控管、Cookie未保護、密碼強度過弱等等。

###  例如：  
　應用程式SESSION Timeout沒有設定。使用者在使用公用電腦登入後卻沒有登出，只是關閉視窗。攻擊者在經過一段時間之後使用同一台電腦，卻可以直接登入。
 
　網站並沒有使用SSL / TLS加密，使用者在使用一般網路或者無線網路時，被攻擊者使用Sniffer竊聽取得User ID、密碼、SESSION ID等，進一步登入該帳號。
 
　這些都是身分驗證功能缺失的例子。 
 
 
  ### 管理者必須做以下的檢查：

1.所有的密碼、Session ID、以及其他資訊都有透過加密傳輸嗎？
2.憑證都有經過加密或hash保護嗎？
3.驗證資訊能被猜測到或被其他弱點修改嗎？
4.Session ID是否在URL中暴露出來？
5.Session ID是否有Timeout機制？

  ### 防護建議：
  
> * 使用完善的COOKIE / SESSION保護機制
> * 不允許外部SESSION
> * 登入及修改資訊頁面使用SSL加密
> * 設定完善的Timeout機制
> * 驗證密碼強度及密碼更換機制  使用完善的COOKIE / SESSION保護機制
> * 不允許外部SESSION
> * 登入及修改資訊頁面使用SSL加密
> * 設定完善的Timeout機制
> * 驗證密碼強度及密碼更換機制 

# A4 - XML External Entity，XEE (XML 外部處理器漏洞)

XML 外部處理器漏洞，主要是因為以 XML 為基礎的網路應用程式沒有管控好權限，直接處理 XML 語法的請求或上傳，此時攻擊者僅需要加入一個惡意的 XML 文件，就能夠鎖定 XML 處理器漏洞進行攻擊，進而導致資料外洩的風險。更進一步，目前 XML 訊息主要採用簡單物件存取協定 (Simple Object Access Protocal，SOAP) 簡化網路應用程式訊息傳遞的標準格式，此時若是採用 SOAP 1.2 之前版本的訊息交換格式，則預設皆有 XML 外部處理器漏洞的風險，因此容易遭受到阻斷式服務的攻擊。所以建議採用 SOAP 1.2 版本避免因為 XML 外部處理器漏洞的風險遭受到阻斷式服務的攻擊。
https://thief.one/2017/06/20/1/
https://itw01.com/V82SUEL.html
https://www.itread01.com/content/1518717376.html



