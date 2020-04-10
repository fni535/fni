# **原理**
解释型语言边编译边运行，因为用户构造恶意参数，拼接到后端执行
语句 select * from admin where username = ‘输入的用户名’ and  password = ‘用户输入的密码’
select * from admin where username =‘  ‘ or 1=1 -- ' and  password = ‘用户输入的密码’

# **Mysql注入**
<u>Mysql5.0+</u>
information_shcema:
	schemata:schema_name
	table:tabel_schema
	columns:table_schema,table_name,column_name

<u>syntax</u>
select columns from table where columns1 = 'value1'  and columns2 = 'value2'·······
insert into table(columns1,columns2,columns3) values (value1,value2,value3)
update table set columns = new_value where columns = value
delete from table where columns = value

```mysql
CREATE TABLE `test`.`admin`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NULL,
  `password` varchar(255) NULL,
  PRIMARY KEY (`id`)
);

SELECT * FROM `admin` WHERE username = 'admin';
INSERT INTO admin(id,username,password) VALUES (4,'admin4','admin4');
INSERT INTO admin(id,username,password) VALUES (5,'admin5','admin5');
UPDATE admin set password = 'admin444' where username = 'ADMIN4';
DELETE FROM admin WHERE username = 'admin5';
```
---

```
CREATE TABLE `test`.`admin`  (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NULL,
  `password` varchar(255) NULL,
  PRIMARY KEY (`id`)
)
> OK
> 时间: 0.033s


SELECT * FROM `admin` WHERE username = 'admin'
> OK
> 时间: 0.012s


INSERT INTO admin(id,username,password) VALUES (4,'admin4','admin4')
> Affected rows: 1
> 时间: 0.013s


INSERT INTO admin(id,username,password) VALUES (5,'admin5','admin5')
> Affected rows: 1
> 时间: 0.013s


UPDATE admin set password = 'admin444' where username = 'ADMIN4'
> Affected rows: 1
> 时间: 0.012s


DELETE FROM admin WHERE username = 'admin5'
> Affected rows: 1
> 时间: 0.013s

```

![结果](.\image\SQLI\SQL_syntax1.PNG)

# **sqlmap**
sqlmap -r http_package_filename -p target 
sqlmap -u "target_url" -D database_name -T table_name --columns(-C word1,word2,word3)