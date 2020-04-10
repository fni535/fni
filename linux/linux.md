#### 配置系统配置：

1. ##### SSH远程登陆配置：

   cd /etc/ssh  cp sshd_config sshd_config.date

   Port 22
   AddressFamily any
   ListenAddress 0.0.0.0
   ListenAddress ::

   HostKey /etc/ssh/ssh_host_rsa_key
   HostKey /etc/ssh/ssh_host_dsa_key
   HostKey /etc/ssh/ssh_host_ecdsa_key
   HostKey /etc/ssh/ssh_host_ed25519_key

   Ciphers and keying
   RekeyLimit default none

   Logging
   SyslogFacility AUTH
   SyslogFacility AUTHPRIV
   LogLevel INFO

   Authentication:

   LoginGraceTime 30m
   PermitRootLogin yes
   StrictModes yes
   MaxAuthTries 1
   MaxSessions 10

   PubkeyAuthentication yes

   The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
   but this is overridden so installations will only check .ssh/authorized_keys
   AuthorizedKeysFile .ssh/authorized_keys

   AuthorizedPrincipalsFile none

   AuthorizedKeysCommand none
   AuthorizedKeysCommandUser nobody

   For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
   HostbasedAuthentication no
   Change to yes if you don't trust ~/.ssh/known_hosts for
   HostbasedAuthentication
   IgnoreUserKnownHosts no
   Don't read the user's ~/.rhosts and ~/.shosts files
   IgnoreRhosts yes

   To disable tunneled clear text passwords, change to no here!
   PasswordAuthentication yes
   PermitEmptyPasswords no

   Change to no to disable s/key passwords
   ChallengeResponseAuthentication yes
   ChallengeResponseAuthentication no

   Kerberos options
   KerberosAuthentication no
   KerberosOrLocalPasswd yes
   KerberosTicketCleanup yes
   KerberosGetAFSToken no
   KerberosUseKuserok yes

   GSSAPI options
   GSSAPIAuthentication yes
   GSSAPICleanupCredentials no
   GSSAPIStrictAcceptorCheck yes
   GSSAPIKeyExchange no
   GSSAPIEnablek5users no

   Set this to 'yes' to enable PAM authentication, account processing,
   and session processing. If this is enabled, PAM authentication will
   be allowed through the ChallengeResponseAuthentication and
   PasswordAuthentication.  Depending on your PAM configuration,
   PAM authentication via ChallengeResponseAuthentication may bypass
   the setting of "PermitRootLogin without-password".
   If you just want the PAM account and session checks to run without
   PAM authentication, then enable this but set PasswordAuthentication
   and ChallengeResponseAuthentication to 'no'.
   WARNING: 'UsePAM no' is not supported in Red Hat Enterprise Linux and may cause several
   problems.
   UsePAM yes

   AllowAgentForwarding yes
   AllowTcpForwarding yes
   GatewayPorts no
   X11Forwarding yes
   X11DisplayOffset 10
   X11UseLocalhost yes
   PermitTTY yes
   PrintMotd yes
   PrintLastLog yes
   TCPKeepAlive yes
   UseLogin no
   UsePrivilegeSeparation sandbox
   PermitUserEnvironment no
   Compression delayed
   ClientAliveInterval # 指定了服务器端向客户端请求消息的时间间隔, 默认是0 ,不发送。检测它是否存在，不存时即断开连接 
   ClientAliveCountMax 3 # 指如果发现客户端没有相应，则判断一次超时，这个参数设置允许超时的次数 

   export TMOUT=60  # 60秒断开ssh会话连接 export TMOUT=0 永不断开 

   ShowPatchLevel no
   UseDNS yes
   PidFile /var/run/sshd.pid
   MaxStartups 10:30:100
   PermitTunnel no
   ChrootDirectory none
   VersionAddendum none

   no default banner path
   Banner none

   Accept locale-related environment variables
   AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
   AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
   AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
   AcceptEnv XMODIFIERS

   override default of no subsystems
   Subsystem sftp  /usr/libexec/openssh/sftp-server

   Example of overriding settings on a per-user basis
   Match User anoncvs
   X11Forwarding no
   AllowTcpForwarding no
   PermitTTY no
   ForceCommand cvs server
   PermitRootLogin yes
   PasswordAuthentication yes
   UseDNS no

   重启服务： service sshd restart 

2. ##### 更新yum阿里源：

   更换之前确保自己安装wget

   ```
   yum list wget
   ```

   若没有安装：

   复制代码

   ```
   yum -y install wget
   ```

   首先备份原版

   ```
   mv /etc/yum.repos.d/CentOS-Base.repo etc/yum.repos.d/CentOS-Base.repo.bak
   ```

   下载阿里的`yum源`配置文件，放入/etc/yum.repos.d/CentOS-Base.repo

   ```
   sudo wget -O CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
   ```

   运行yum makecache生成缓存

   ```
   yum clean all
   yum makecache
   ```
   
   
   
3. ##### 开机启动进程：systemctl

   

4.  tee指令会从标准输入设备读取数据，将其内容输出到标准输出设备，同时保存成文件。 

   ```
   tee [-ai][--help][--version][文件...]
   -a或--append 　附加到既有文件的后面，而非覆盖它．
   -i或--ignore-interrupts 　忽略中断信号。
   --help 　在线帮助。
   --version 　显示版本信息。
   ```





#### bash操作命令：

##### 		

##### 		查找文件中文字**grep** ：-[options] [path]

​		-E ：开启扩展（Extend）的正则表达式。

　　-i ：忽略大小写（ignore case）。

　　-v ：反过来（invert），只打印没有匹配的，而匹配的反而不打印。

　　-n ：显示行号

　　-w ：被匹配的文本只能是单词，而不能是单词中的某一部分，如文本中有liker，而我搜寻的只是like，就可以使用-w选项来避免匹配liker

　　-c ：显示总共有多少行被匹配到了，而不是显示被匹配到的内容，注意如果同时使用-cv选项是显示有多少行没有被匹配到。

　　-o ：只显示被模式匹配到的字符串。

　　--color :将匹配到的内容以颜色高亮显示。

　　-A  n：显示匹配到的字符串所在的行及其后n行，after

　　-B  n：显示匹配到的字符串所在的行及其前n行，before

　　-C  n：显示匹配到的字符串所在的行及其前后各n行，context

​		-r, --recursive 会递归指定目录下的所有文件，并匹配其内容

​		 -l,： 查看匹配到的内容所在文件的名称 

##### 	查找文件 find：find   [path   ] [-option] [-print ]   [ -exec   -ok   command ]   {} \;

​			-mount, -xdev : 只检查和指定目录在同一个文件系统下的文件，避免列出其它文件系统中的文件

​			-amin n : 在过去 n 分钟内被读取过

​			-anewer file : 比文件 file 更晚被读取过的文件

​			-atime n : 在过去n天内被读取过的文件

​			-cmin n : 在过去 n 分钟内被修改过

​			-cnewer file :比文件 file 更新的文件

​			-ctime n : 在过去n天内被修改过的文件

​			-empty : 空的文件-gid n or -group name : gid 是 n 或是 group 名称是 name

​			-ipath p, -path p : 路径名称符合 p 的文件，ipath 会忽略大小写

​			-name name, -iname name : 文件名称符合 name 的文件。iname 会忽略大小写

​			-size n : 文件大小 是 n 单位，b 代表 512 位元组的区块，c 表示字元数，k 表示 kilo bytes，w 是二个位元组。

​			-type c : 文件类型是 c 的文件。

##### 	查找路径 whereis 

# 1 tar

### 1.2 tar介绍

  tar命令是linux系统中对文件和目录解压缩命令。tar命令可以用于对后缀名为`.tar`,`tar.gz`等常用文件。

### 1.3 tar参数

- -c：创建新的**压缩**文件
- -x ：从压缩的文件中**解压**文件
- -v ：显示解压缩操作的过程
- -f ：指定压缩文件
- -z ：支持**gzip**解压文件
- -C ：切换到指定目录
- -r：添加文件至已压缩文件
- -u： 添加改变了和现有的文件到已经存在的压缩文件
- -t ：显示压缩文件的内容目录结构等
- -j ：支持bzip2解压文件
- -k ：解压时不覆盖当前目录下原有文件
- --delete：删除压缩包内的文件

### 1.4 tar压缩

**1.4.1 压缩tar包**
使用`-c`参数
多个文件压缩：
`tar -cvf t.tar t1.txt t2.txt`
目录压缩：
`tar -cvf dir.tar dir1/`
匹配压缩：
`tar -cvf t.tar *.txt`

**1.4.2 压缩tar.gz包**
使用`-z`参数
压缩为gizp
`tar -zcvf t.tar.gz t1.txt t2.txt`

**1.4.3 压缩gar.bz2包**
使用`-j`参数
压缩为bzip2
`tar -jcvf t.tar.bz2 t1.txt t2.txt`

**1.4.4 查看压缩包内容**
使用`-t`参数
`tar -tvf t.tar`

**1.4.5 向压缩包添加/更新文件**
使用`-r`参数
`tar -rf t.tar newfile`

**1.4.6 删除压缩包内的文件**
如t.tar内包含了t1.txt和其他文件，需删除t1.txt文件，使用`--delete`参数，需要注意删除文件的目录是全路径。
`tar -f t.tar --delete /t/t1.txt`

**1.4.7 压缩时删除源文件**
慎用，如果删除源文件较多时，可以使用这个命令。
`tar -zcvf t.tar.gz t1.txt --remove-files`

### 1.5 tar解压

**1.5.1 直接解压到当前目录**
使用`-x`参数
`tar -xvf t.tar`

**1.5.2 解压到指定目录**
使用`-C`参数
`tar -xvf t.tar -C dir`

**1.5.3 解压包中的某些文件**
`tar -xvf t.tar t/t1.txt -C dir1`
如上，将t.tar压缩包中的t1.txt解压至dir1目录。

**1.5.4 解压不覆盖原有文件**
使用`-k`参数
`tar -xvkf t.tar`

**1.5.5 去除目录结构**
使用`--strip-components`，如去掉一层目录
`tar -xvf t.tar.gz --strip-components=1`

# 2 zip/unzip

### 2.1 zip/unzip介绍

  zip和unzip命令主要用于处理zip包，但是我们也可以用unzip去解压jar包。

### 2.2 zip/unzip参数

**zip参数**

常用：

- -f 与"-u"参数类似，更新/创建文件；
- -d 删除压缩文件内指定的文件；
- -r 递归处理指定目录及子目录；
- -j 只压缩该目录下的所有文件，不带目录名。
- -u 更换较新的文件到压缩文件内。
- -v 显示指令执行过程或显示版本信息。
- -y 直接保存符号连接，而非该连接所指向的文件，本参数仅在UNIX之类的系统下有效。

**unzip参数**

常用参数说明：

- -l 显示压缩包内文件
- -j 只保存文件名称及其内容，而不存放任何目录名称。
- -o 以压缩文件内拥有最新更改时间的文件为准，将压缩文件的更改时间设成和该
- -v 显示指令执行过程或显示版本信息。
- -d 指定解压目录，目录不存在会创建

### 2.1 压缩 zip

**2.1.1 压缩目录**
使用`-r`参数
`zip -r t.zip dir/`

**2.1.2 压缩目录下的文件，不带目录名**
使用`-j`参数
`zip -rj t.zip dir/`

**2.1.3 删除压缩包内的指定文件**
使用`-d`参数，如删除t.zip中的t1.txt文件：
`zip -d t.zip t1.txt`

### 2.2 解压 unzip

**2.2.1 查看解压包的文件信息**
使用`-l`参数
`unzip -l t.zip`

**2.2.2 查看解压包内的文件详细信息**
使用`-v`参数
`unzip -v t.zip`

**2.2.3 解压压缩包到当前目录**
使用`-o`参数
`unzip -o t.zip`

**2.2.4 解压压缩包到指定目录**
使用`-d`参数
`unzip -o t.zip -d test/`

**2.2.5 解压压缩包内的指定文件**
`unzip -o t.zip "t2.txt" -d t2_dir`

**2.2.6 解压jar包**
`unzip -o service-1.jar -d service_dir`

# 1 yum

```
yum install 
yum update
yum check-update 
yum upgrade package1 
yum groupupdate group1 
yum info package1 
yum list/yum list installed
yum clean packages 
yum clean headers 
yum clean oldheaders 
yum clean, yum clean all (= yum clean packages; yum clean oldheaders) 
yum remove
```