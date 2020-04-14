二.Sq]注入介绍下、怎么防御具体防御函数、拼接语句问题怎么产生的能举一个具体的代码例子

------

PHP是解释型语言，会边执行边编译，在用户故意输入恶意参数时，会夹带进本身后端语句执行，
**<u>盲注</u>**：网站页面在输入条件为true和false的情况下会显示不同，但页面中没有输出。此时需要在SQL语句之后添加条件判断。

​	猜解数据库：先构造条件判断当前数据库的名字长度，然后逐字猜解数据库名。
​	猜解数据表：先构造条件判断数据表的数量，然后逐个进行猜解，先猜解表名长度然后逐字猜解表名。
​	猜解数据列：指定数据库中的指定表进行猜解字段，首先猜解字段的数目，然后逐个猜解字段
​	猜解内容：指定数据列，先查询数据的条数，然后逐条猜解其中的内容

**<u>基于时间的盲注</u>**：网站页面在输入条件为真和为假返回的页面相同，但通过延时函数构造语句，可通过页面响应时间的不同判断是否存在注入
猜解思路：
类似基于布尔的盲注，只是将条件为真转换为延时响应

<u>**基于UNION的注入**</u>：首先通过order by 进行判断查询参数的数目，然后构造union查询，查看回显。有时需要将前面参数名修改为假的参数。如id=-10’ union select 1,2，查找页面中1和2的位置，在页面中显示的数字的地方构造查询的内容。
若页面无回显但报错可以尝试报错注入

**<u>宽字节注入</u>**
宽字节注入的原理即为数据库的编码与后台程序的编码不一致，数据库中一个字符占两个字节，而后台程序为一个字符占一个字节，当后台程序对输入的单引号的字符进行转义时，通过在这些转义的字符前输入%bf然后将%bf’带入后台程序时会转义为%bf’，此时带入数据库中，数据库将%bf\看作是一个中文字符从而使用单引号将SQL语句进行闭合。
**<u>防御**</u>

preg_replace

addslashes() 是强行加/；

mysql_real_escape_string()  会判断字符集，但是对PHP版本有要求

magic_quotes_gpc

2.采用了PreparedStatement，就会将sql语句："select id, no from user where id=?" 预先编译好，也就是SQL引擎会预先进行语法分析，产生语法树，生成执行计划，也就是说，后面你输入的参数，无论你输入的是什么，都不会影响该sql语句的 语法结构了，因为语法分析已经完成了，而语法分析主要是分析sql命令，比如 select ,from ,where ,and, or ,order by 等等。所以即使你后面输入了这些sql命令，也不会被当成sql命令来执行了，因为这些sql命令的执行， 必须先的通过语法分析，生成执行计划，既然语法分析已经完成，已经预编译过了，那么后面输入的参数，是绝对不可能作为sql命令来执行的，**只会被当做字符串字面值参数**

3.但是不是所有场景都能够采用 sql语句预编译，有一些场景必须的采用 字符串拼接的方式，此时，我们严格检查参数的数据类型，还有可以使用一些安全函数，来方式sql注入.在接收到用户输入的参数时，我们就严格检查 id，只能是int型。复杂情况可以使用正则表达式来判断。这样也是可以防止sql注入的。

4.严格限制数据库管理用户的权限。

　　将数据库用户的功能设置为最低要求；这将限制攻击者在设法获取访问权限时可以执行的操作。

三.sql注入预编译怎么防御。语句应该怎么写

**采用sql语句预编译和绑定变量，是防御sql注入的最佳方法**。

<?php
//预编译不仅可以提高效率，还可以防止SQL注入攻击
$mysqli=new mysqli("localhost", "root", "root", "test303");
if($mysqli->connect_error){
die("连接失败！".$mysqli->connect_error);
}
//1.穿件预编译对象
$sql="insert into account values(?,?);";
$mysqli_stmt=$mysqli->prepare($sql);//$mysqli->prepare准备执行SQL语句
//2.绑定参数
$id=4;
$account=400;
//3.将绑定的值赋值为？，类型要一直
$mysqli_stmt->bind_param("ii", $id, $account); //绑定变量来一份声明中作为参数
//4.执行
$res=$mysqli_stmt->execute();//执行准备好的查询
if (!$res){
die("操作失败".$mysqli_stmt->error);
}else {
echo "操作成功！";
}
//5.释放资源
$mysqli->close();
?>

4.ssrf原理

SSRF(Server-Side Request Forgery:服务器端请求伪造) 是一种由攻击者构造形成由服务端发起请求的一个安全漏洞。一般情况下，SSRF攻击的目标是从外网无法访问的内部系统。(边界)，SSRF 形成的原因大都是由于服务端提供了从其他服务器应用获取数据的功能且没有对目标地址做过滤与限制。比如从指定URL地址获取网页文本内容，加载指定地址的图片，下载等等。

##### 漏洞验证

1.排除法：浏览器f12查看源代码看是否是在本地进行了请求

2.dnslog等工具进行测试，看是否被访问

--可以在盲打后台用例中将当前准备请求的uri 和参数编码成base64，这样盲打后台解码后就知道是哪台机器哪个cgi触发的请求。

3.抓包分析发送的请求是不是由服务器的发送的，如果不是客户端发出的请求，则有可能是，接着找存在HTTP服务的内网地址

--从漏洞平台中的历史漏洞寻找泄漏的存在web应用内网地址

--通过二级域名暴力猜解工具模糊猜测内网地址

4.直接返回的Banner、title、content等信息

5.留意bool型SSRF

##### 漏洞利用

1.让服务端去访问相应的网址

2.让服务端去访问自己所处内网的一些指纹文件来判断是否存在相应的cms

3.可以使用file、dict、gopher[11]、ftp协议进行请求访问相应的文件

4.攻击内网web应用（可以向内部任意主机的任意端口发送精心构造的数据包{payload}）

5.攻击内网应用程序（利用跨协议通信技术）

6.判断内网主机是否存活：方法是访问看是否有端口开放

7.DoS攻击（请求大文件，始终保持连接keep-alive always）

##### 绕过

1.http://baidu.com@www.baidu.com/与http://www.baidu.com/请求时是相同的

2.各种IP地址的进制转换

3.URL跳转绕过：http://www.hackersb.cn/redirect.php?url=http://192.168.0.1/

4.短网址绕过 http://t.cn/RwbLKDx

5.xip.io来绕过：http://xxx.192.168.0.1.xip.io/ == 192.168.0.1 (xxx 任意）

指向任意ip的域名：xip.io(37signals开发实现的定制DNS服务)

6.限制了子网段，可以加 :80 端口绕过。http://tieba.baidu.com/f/commit/share/openShareApi?url=http://10.42.7.78:80

7.探测内网域名，或者将自己的域名解析到内网ip

8.例如 http://10.153.138.81/ts.php , 修复时容易出现的获取host时以/分割来确定host，

但这样可以用 http://abc@10.153.138.81/ 绕过

5.无回显利用方式，修复方案（具体到某种语言对应的函数）

6.csrf防御

**增加token验证（常用的做法）：**

　　1、对关键操作增加token参数，token值必须随机，每次都不一样；

　　**关于安全的会话管理（避免会话被利用）：**（我们之前说过CSRF的攻击必须是登录态）

　　1、不要在客户端保存敏感信息（比如身份认证信息）；

　　2、测试直接关闭，退出时，的会话过期机制；

　　3、设置会话过期机制，比如15分钟内无操作，则自动登入超时；

　　**访问控制安全管理：**

　　1、敏感信息的修改时需要对身份进行二次认证，比如修改账号时，需要判断旧密码；

　　2、敏感信息的修改尽量使用post，而不是get；（post的安全性比get高些）

　　3、通过http 头部中的referer来限制原页面（比如修改个人信息的referer必须来自本域，不能是其他域的或者没有referer）

　　**增加验证码**（也可以看成　小token但需要人机交互）**：**

　　一般用在登录（防暴力破解），也可以用在其他重要信息操作的表单中（需要考虑可用性）

7.csrf加token值具体实现过程（具体到某种语言对应的函数）
8.nmap使用过程，几种扫描方式区别是什么

#### tcp connect()

这种方式最简单。直接与被扫描的端口建立tcp链接，如果成功，则说明端口开放，如果不成功则说明端口关闭的。这种扫描的特点是与被扫描端口建立完成的tcp链接，完整的tcp三次握手。优点主要是不需要root权限即可扫描端口。因为connect可以在用户态直接调用

#### TCP SYN scanning

这种扫描方式又被称为tcp半开放扫描。顾名思义，这种扫描不需要建立完整的tcp连接，即可扫描端口的状态。发送tcp syn数据包，这个也是tcp握手的第一个包。如果端口开放，则会返回 tcp syn+ack数据包。如果端口关闭，则返回 tcp rst数据包。这样我们就不用进行tcp 握手的第三步，也可以探测端口的状态。这种扫描需要构建raw socket。所以需要root权限

#### TCP FIN scanning

有些时候防火墙绘过滤tcp syn数据包，有些时候会记录syn数据包并检测时候有nmap扫描。这时候可以使用TCP FIN scanning。这种方式很简单。发送tcp FIN数据包到待测端口。如果返回RST数据包，则说明该端口关闭，如果无返回则说明该端口开放。这时tcp协议的一个BUG，所以这种扫描方式不一定百分之百可靠（例如windows），但是这种扫描方式适合大部分 *NIX 系统。

#### TCP NULL, FIN, and Xmas scans

在RFC 793的第65页写到，如果目的端口的是关闭的，并且接受到的tcp数据包如果可能会导致系统错误，则返回RST。如果开放的端口接受到诸如SYN RST ACK，则丢弃或者不做任何处理。根据此RFC描述，我们可以发送不包含SYN RST或者ACK标志的数据包，如果返回RST则说明端口是关闭状态，如果什么都没有返回则说明端口是开放状态。



9.wiresark筛查某个IP对应的语句
10.snort规则编写（给你一个weblogic反序列化漏洞应该怎么快速进行特征提取防御）具体语句

11.weblogic反序列化通过什么协议攻击的

Weblogic的T3协议。

12，连接一个小马，流量层有什么特征

PHP类WebShell链接流量

第一：“eval”，eval函数用于执行传递的攻击payload，这是必不可少的；

第二：(base64_decode($_POST[z0]))，(base64_decode($_POST[z0]))将攻击payload进行Base64解码，因为菜刀默认是将攻击载荷使用Base64编码，以避免被检测；

第三：&z0=QGluaV9zZXQ...，该部分是传递攻击payload，此参数z0对应$_POST[z0]接收到的数据，该参数值是使用Base64编码的，所以可以利用base64解码可以看到攻击明文。

JSP类WebShell链接流量：

该流量是WebShell链接流量的第一段链接流量，其中特征主要在i=A&z0=GB2312，菜刀链接JSP木马时，第一个参数定义操作，其中参数值为A-Q，如i=A，第二个参数指定编码，其参数值为编码，如z0=GB2312，有时候z0后面还会接着又z1=参数用来加入攻击载荷。

注：其中参数名i、z0、z1这种参数名是会变的，但是其参数值以及这种形式是不会变得，最主要就是第一个参数值在A-Q，这种是不变的。

ASP类WebShell链接流量

“Execute”，Execute函数用于执行传递的攻击payload，这是必不可少的，这个等同于php类中eval函数；

第二：OnError ResumeNext，这部分是大部分ASP客户端中必有的流量，能保证不管前面出任何错，继续执行以下代码。

第三：Response.Write和Response.End是必有的，是来完善整个操作的。

这种流量主要识别这几部分特征，在正常流量中基本没有。





13，上传如何绕过态势感知设备

14，如何使用流量加密绕过上传waf（木马怎么加密具体调用哪些函数）

中转webshell的逻辑很简单，菜刀不直接向shell发送数据，而是发送到中转的一个页面上，这个页面对接收的参数全部进行加密（甚至可以用2048位的RSA，只要你愿意），然后再发送给shell，shell接收后先用同样的算法进行解密，然后对执行的结果进行加密，返回给中转shell，中转shell再去解密，然后返回给菜刀客户端

15.sql注入过waf怎么过，请举出一个具体的案例

```
and  /*!1=1*/
%23%0a  1=1
order%23%0aby 1
union%23xxx%0aselect 不拦截
union-- xxx%0aselect 不拦截
union--+xxx%0aselect 不拦截
database() -->database/**/()
database() -->database/*!()*/
user()  --> user/**/() 
user() -->user/*!()*/
```

16，忘记密码处通常会存在什么逻辑漏洞（请举出具体案例）

任意用户密码找回、验证码可绕过等问题。（前端验证，验证码爆破，任意用户密码重置）

17，短信轰炸提示操作频繁应该怎么绕过

代理池

18，受到ms-17-010攻击的机器都有哪些特征，除了打补丁还有什么方法进行防御

可能会导致电脑蓝屏或者卡死,但是有些电脑卡死一会就会恢复

445端口

19，如何查找真是IP

## nslookup 

使用各种多地 ping 的服务

### 查询历史DNS记录

### 查询子域名

shodan，fofa

证书透明性

### 利用HTTP标头寻找真实原始IP

### 利用网站返回的内容寻找真实原始IP

### 使用国外主机解析域名

### 网站邮件订阅查找

1.mysql查表名
	5.0一下猜表明 ，以上通过information_schema
	如果禁用了information
		1.Innodb引擎的注入 
			在Mysql 5.6以上的版本中，在系统Mysql库中存在两张与innodb相关的表：innodb_table_stats和innodb_index_stats。
				mysql> select * from flag where flag=1 union select group_concat(table_name) from mysql.innodb_table_stats where database_name=database();
		2.sys schemma
			mysql在5.7版本中新增特征sys schemma
				基础数据来自于performance_chema和information_schema两个库，本身数据库不存储数据。
		3.猜表
参考：https://www.anquanke.com/post/id/193512

2.nmap与masscan区别	     	
	 masscan号称是世界上最快的扫描软件，可以在3分钟内扫描整个互联网上的所有端口。 
	 masscan采用了异步传输方式，无状态的扫描方式。
	 nmap需要记录tcp/ip的状态，OS能够处理的TCP/IP连接最多为1500左右。
	

	nmap原理
		Nmap采用TCP/IP协议栈指纹进行目标主机的操作系统类型判断
	masscan原理				masscan与目标主机不建立完整的TCP连接，扫描者主机先向目标主机发送一个SYN请求连接数据包，目标主机会向扫描者主机回复一个SYN/ACK确认连接数据包，当扫描者主机收到目标主机发送回来的SYN/ACK确认连接数据包之后，扫描者主机向目标主机发送RST结束连接。选项–banners除外(因为要获取banner信息，必须要进行完整的三次握手)。

3.shodan与fofa
	国内fofa好用资产多，shodan vip可以直接搜cv
原理:	基本上来讲是通过端口扫描。shodan不定时的扫描全网的IP地址。通过得到的Banner等情报来判断该端口所对应的service。工控设备有自己独自的通信协议，但对于比较有名的协议比如Modbus,DNP3,bacnet，Shodan都会有对应的扫描程序，根据设备回应的数据来做分析。具体可以参考Nmap的Script设定的部分。

4.tcp包过程
	三次握手

5.Java反序列化原理

6.常用的扫描软件
	自己编写的扫描器+awvs

7.最厉害的漏洞

8.绕waf 的方式
	分块传输、脏字符、协议绕waf

1.jwt
JSON Web Token (JWT)，它是目前最流行的跨域身份验证解决方案
危害：
敏感信息泄露
	我们能够轻松解码payload和header，因为这两个都只经过Base64Url编码，而有的时候开发者会误将敏感信息存在payload中。
未校验签名
	某些服务端并未校验JWT签名，所以，可以尝试修改signature后(或者直接删除signature)看其是否还有效。
	JWT tool可对其做测试

2.session token cookie 区别
session ： 会话窗口
token：签名
cookie ： 身份认证

3.weblogic常见漏洞
反序列化
任意文件上传
ssrf
弱口令
XMLDecoder反序列化

4.最近复现哪些漏洞
cve-2020-2555（weblogic反序列化）

cve-2020-0796（smb v3）

5.常见端口与信息
873 rsync
53 DNS
139 smb
445 smb
389 LDAP
1433 mssql
1521 oracle 
2375 docker
3389 RDP 
3306 mysql
7001\7002 webloic
8009  TOMCAT AJP
8080 tomcat
9200 elk未授权
11211 mogodb 未授权

5.报错注入函数，与原理 
upadtexml
extractvalue
exp
floor

XPATH语句
mysql版本号大于5.1.5 回显不能超过32位

exp函数溢出错误：
适用版本：mysql5.5.44-5.5.47.

低版本可使用 列名重复报错
name_const（）


6.sql注入写shell语句、写shell条件
mysql账户有 File_priv 权限
知道绝对路径
有写入权限
select '语句' into outfile '地址'
可以写入日志文件里

7.跨域资源存在哪些问题
CORS 
JSON

8.json劫持
JSONP漏洞利用过程如下：
1）用户在网站B 注册并登录，网站B 包含了用户的id，name，email等信息；
2）用户通过浏览器向网站A发出URL请求；
3）网站A向用户返回响应页面，响应页面中注册了 JavaScript 的回调函数和向网站B请求的script标签
挖掘方式
查看是否存在callback 函数  
接口是否存在跨域

9.如何查找域
DNS解析记录
spn扫描
net group 查询
端口识别
	53 DNS主机
	389 lDAP 

10.端口转发常用软件
HTTP 协议
 reGeorg
 tunna
tcp
 portfwd
 Termite
建立隧道 内网穿刺
 ngrok
 fpm

11.内网进去干什么
信息收集
（域控、环境变量、杀软、补丁、注册信息、用户组的信息、IP信息、本地端口链接情况、日志信息）
提权
 （漏洞提权、第三方、系统配置）
横向渗透
 （先把机器做成跳板、漏洞攻击、钓鱼、minikatz抓票据、伪造白银票据） 主要看信息收集了哪些东西
拿域控

### IIS

目录解析(6.0)
形式：www.xxx.com/xx.asp/xx.jpg
原理: 服务器默认会把.asp，.asa目录下的文件都解析成asp文件。

文件解析
形式：www.xxx.com/xx.asp;.jpg
原理：服务器默认不解析;号后面的内容，因此xx.asp;.jpg便被解析成asp文件了。

解析文件类型
IIS6.0 默认的可执行文件除了asp还包含这三种 :

/test.asa
/test.cer
/test.cdx

**IIS 7.0/IIS 7.5/ Nginx <0.8.3畸形解析漏洞**

在默认Fast-CGI开启状况下，访问以下网址，服务器将把xx.jpg文件当做php解析并执行。
 `http://www.xxx.com/xx.jpg/.php`



### Apache

Apache 解析文件的规则是从右到左开始判断解析,如果后缀名为不可识别文件解析,就再往左判断。比如 test.php.owf.rar “.owf”和”.rar” 这两种后缀是apache不可识别解析,apache就会把wooyun.php.owf.rar解析成php。

（1）如果在 Apache 的 conf 里有这样一行配置 AddHandler php5-script .php 这时只要文件名里包含.php 即使文件名是 test2.php.jpg 也会以 php 来执行。
（2）如果在 Apache 的 conf 里有这样一行配置 AddType application/x-httpd-php .jpg 即使扩展名是 jpg，一样能以 php 方式执行。

修复：

1.apache配置文件，禁止.php.这样的文件执行，配置文件里面加入

```
<Files ~ “.(php.|php3.)”>
        Order Allow,Deny
        Deny from all
</Files>
```

2.用伪静态能解决这个问题，重写类似.php.*这类文件，打开apache的httpd.conf找到LoadModule rewrite_module modules/mod_rewrite.so
把#号去掉，重启apache,在网站根目录下建立.htaccess文件,代码如下:

```
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteRule .(php.|php3.) /index.php
RewriteRule .(pHp.|pHp3.) /index.php
RewriteRule .(phP.|phP3.) /index.php
RewriteRule .(Php.|Php3.) /index.php
RewriteRule .(PHp.|PHp3.) /index.php
RewriteRule .(PhP.|PhP3.) /index.php
RewriteRule .(pHP.|pHP3.) /index.php
RewriteRule .(PHP.|PHP3.) /index.php
</IfModule>
```

### Nginx