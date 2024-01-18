#!/bin/bash
clear
echo ""
echo " ____________________________________________________________________ "
echo "|                                                                    |"
echo "|          Local Information gather Script for Linux                 |"
echo "|                                                                    |"
echo "|____________________________________________________________________|"
echo ""
echo ""

LOG_NAME="Local-Information_"`date +"%Y-%m-%d"`".log"

echo "" > "$LOG_NAME"
echo " ____________________________________________________________________ " >> "$LOG_NAME"
echo "|                                                                    |" >> "$LOG_NAME"
echo "|          Local Information gather Script for Linux                 |" >> "$LOG_NAME"
echo "|                                                                    |" >> "$LOG_NAME"
echo "|____________________________________________________________________|" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"

# 基本信息
IP=`ifconfig -a | grep inet|grep -v "127.0.0.1" | awk '{print $2}'| head -n 3`
HOSTNAME=`hostname`
OS=`uname -s` 
SSH_V=`ssh -V`
echo "0.基本信息收集" >> "$LOG_NAME"
echo ""
echo "ip: "$IP >> "$LOG_NAME"
echo "hostname: "$HOSTNAME >> "$LOG_NAME"
echo "os: "$OS >> "$LOG_NAME"
echo "ssh_version: "$SSH_V >> "$LOG_NAME" 2>&1

# 1.身份鉴别
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "1.身份鉴别" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
# 1.1应采用用户名密码、生物技术、动态口令等一种或多种相结合的身份认证方式。
echo "1.1应采用用户名密码、生物技术、动态口令等一种或多种相结合的身份认证方式。" >> "$LOG_NAME"
echo "$(tput setaf 1)[*******人工测试查看（询问管理员）*******]" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"


# 1.2口令策略设置符合复杂度要求
echo "1.2口令策略设置符合复杂度要求。" >> "$LOG_NAME"
# 检查/etc/login.defs
PASS_MAX_DAYS=`cat /etc/login.defs | grep -v ^# | grep -v ^$ | grep -i PASS_MAX_DAYS | awk '{ print $2 }'`
PASS_MIN_DAYS=`cat /etc/login.defs | grep -v ^# | grep -v ^$ | grep -i PASS_MIN_DAYS | awk '{ print $2 }'`
PASS_MIN_LEN=`cat /etc/login.defs | grep -v ^# | grep -v ^$ | grep -i PASS_MIN_LEN | awk '{ print $2 }'`
PASS_WARN_AGE=`cat /etc/login.defs | grep -v ^# | grep -v ^$ | grep -i PASS_WARN_AGE | awk '{ print $2 }'`
if [ "$PASS_MAX_DAYS" -ne 180 ] || [ "$PASS_MIN_DAYS" -ne 1 ] || [ "$PASS_MIN_LEN" -ne 8 ] || [ "$PASS_WARN_AGE" -ne 28 ]
then
    echo "/etc/login.defs配置不合规" >> "$LOG_NAME"
    echo "cat /etc/login.defs | grep -v ^# | grep -v ^$ | grep -i PASS" >> "$LOG_NAME"
    cat /etc/login.defs | grep -v ^# | grep -v ^$ | grep -i PASS >> "$LOG_NAME" 2>&1
    echo ""  >> "$LOG_NAME"
else
	echo "/etc/login.defs配置合规" >> "$LOG_NAME"
	echo ""  >> "$LOG_NAME"
fi
# 检查/etc/pam.d/system-auth
echo "cat /etc/pam.d/system-auth | grep -v ^# | grep -v ^$ | grep password" >> "$LOG_NAME"
cat /etc/pam.d/system-auth | grep -v ^# | grep -v ^$ | grep password >> "$LOG_NAME" 2>&1
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 检查/etc/shadow
shadow_p=`cat /etc/shadow | grep -v "\!" | grep -v "*" | awk -F: '$4==0 || $5==99999 {print $1}'`
if [ "$shadow_p" != "" ]
then
    echo "/etc/shadow配置不合规" >> "$LOG_NAME"
    echo "cat /etc/shadow | grep -v "\!" | grep -v "*"" >> "$LOG_NAME"
    cat /etc/shadow | grep -v "\!" | grep -v "*" >> "$LOG_NAME" 2>&1
    echo ""  >> "$LOG_NAME"
fi
echo "$(tput setaf 1)[*******人工测试查看（/etc/pam.d/system-auth文件）*******]" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 1.3登录失败处理功能
echo "1.3登录失败处理功能" >> "$LOG_NAME"
echo "cat /etc/pam.d/system-auth | grep -v ^# | grep -v ^$ | grep auth" >> "$LOG_NAME"
cat /etc/pam.d/system-auth | grep -v ^# | grep -v ^$ | grep auth >> "$LOG_NAME" 2>&1
echo "$(tput setaf 1)[*******人工测试查看*******]" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 1.4OpenSSH版本
echo "1.4OpenSSH版本" >> "$LOG_NAME"
echo "ssh -V" >> "$LOG_NAME"
ssh -V >> "$LOG_NAME" 2>&1
echo "$(tput setaf 1)[*******人工测试查看*******]" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 1.5操作系统用户名唯一
echo "1.5操作系统用户名唯一" >> "$LOG_NAME"
passwd_only=`cat /etc/passwd |awk -F: '{print $1,$3}'|sort -t ' ' -k 2n|uniq -f1 -D`
if [ "$passwd_only" != "" ]
then
    echo "操作系统用户名不唯一" >> "$LOG_NAME"
    echo "cat /etc/passwd |awk -F: '{print $1,$3}'|sort -t ' ' -k 2n|uniq -f1 -D" >> "$LOG_NAME"
    cat /etc/passwd |awk -F: '{print $1,$3}'|sort -t ' ' -k 2n|uniq -f1 -D >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
else
	echo "[OK]"  >> "$LOG_NAME"
	echo ""  >> "$LOG_NAME"
fi

# 1.6限制超级管理员帐户远程登录
echo "1.6限制超级管理员帐户远程登录" >> "$LOG_NAME"
echo "$(tput setaf 1)[*******人工测试查看*******]" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"


# 1.7检查设置登录终端的操作超时锁定
# 检查、etc/profile
echo "1.7检查设置登录终端的操作超时锁定" >> "$LOG_NAME"
TMOUT=`cat /etc/profile | grep -v ^# | grep -v ^$ | awk '{ print $2 }'`
if [ TMOUT != 600 ]
then
	echo "cat /etc/profile | grep -v ^# | grep -v ^$ | grep TMOUT" >> "$LOG_NAME"
	cat /etc/profile | grep -v ^# | grep -v ^$ | grep TMOUT >> "$LOG_NAME" 2>&1
	echo "$(tput setaf 1)[未设置登录终端的操作超时锁定]" >> "$LOG_NAME"
else
	echo "[ok]" >> "$LOG_NAME"
fi
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"



# 2.访问控制
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "2.访问控制" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 2.1 启用访问控制功能
echo "2.1.启用访问控制功能" >> "$LOG_NAME"
profile_umask=`umask | awk '{print $1}'`
# 检查umask
if [$profile_umask == '0022']
then
	echo "umask: "$profile_umask >> "$LOG_NAME"
	echo "[umask符合]"  >> "$LOG_NAME"
else
	echo "umask为"$profile_umask >> "$LOG_NAME"
	echo "" >> "$LOG_NAME"
fi
# 文件权限
passwd_rwx=`ls -la /etc/passwd | awk '{print $1}' | awk -F"." '{print $1}'`
group_rwx=`ls -la /etc/group | awk '{print $1}' | awk -F"." '{print $1}'`
shadow_rwx=`ls -la /etc/shadow | awk '{print $1}' | awk -F"." '{print $1}'`
crotab_rwx=`ls -la /etc/crontab | awk '{print $1}' | awk -F"." '{print $1}'`
login_defs_rwx=`ls -la /etc/login.defs | awk '{print $1}' | awk -F"." '{print $1}'`
sshd_rwx=`ls -la /etc/pam.d/sshd | awk '{print $1}' | awk -F"." '{print $1}'`
system-auth-ac_rwx=`ls -la /etc/pam.d/system-auth-ac | awk '{print $1}' | awk -F"." '{print $1}'`
ssh_config_rwx=`ls -la /ssh/ssh_config | awk '{print $1}' | awk -F"." '{print $1}'`
rsyslog_conf_rwx=`ls -la /etc/rsyslog.conf | awk '{print $1}' | awk -F"." '{print $1}'`
auditd_conf_rwx=`ls -la /etc/audit/auditd.conf | awk '{print $1}' | awk -F"." '{print $1}'`
if [ "$passwd_rwx" != "-rw-r--r--" ] || [ "$group_rwx" != "-rw-r--r--" ] || [ "$shadow_rwx" != "-r--------" ] || [ "$crotab_rwx" != "-rw-r--r--" ] || [ "$login_defs_rwx" != "-rw-r--r--" ] || [ "$sshd_rwx" != "-rw-r--r--" ] || [ "$system-auth-ac_rwx" != "-rw-r--r--" ] || [ "$ssh_config_rwx" != "-rw-r--r--" ] || [ "$rsyslog_conf_rwx" != "-r--------" ] || [ "$auditd_conf_rwx" != "-rw-r--r--" ]
then
    echo "文件和目录的权限不合规" >> "$LOG_NAME"
    echo "ls -la /etc/passwd 644" >> "$LOG_NAME"
    ls -la /etc/passwd >> "$LOG_NAME" 2>&1
    echo ""  >> "$LOG_NAME"
    echo "ls -la /etc/group 644" >> "$LOG_NAME"
    ls -la /etc/group >> "$LOG_NAME" 2>&1
    echo ""  >> "$LOG_NAME"
    echo "ls -la /etc/shadow 400" >> "$LOG_NAME"
    ls -la /etc/shadow >> "$LOG_NAME" 2>&1
    echo ""  >> "$LOG_NAME"
	echo "ls -la /etc/crontab 644" >> "$LOG_NAME"
	ls -la /etc/crontab >> "$LOG_NAME" 2>&1
	echo ""  >> "$LOG_NAME"
	echo "ls -la /etc/login.defs 644" >> "$LOG_NAME"
	ls -la /etc/login.defs >> "$LOG_NAME" 2>&1
	echo ""  >> "$LOG_NAME"
	echo "ls -la /etc/pam.d/sshd 644" >> "$LOG_NAME"
	ls -la /etc/pam.d/sshd >> "$LOG_NAME" 2>&1
	echo ""  >> "$LOG_NAME"
	echo "ls -la /etc/pam.d/system-auth-ac 644" >> "$LOG_NAME"
	ls -la /etc/pam.d/system-auth-ac >> "$LOG_NAME" 2>&1
	echo ""  >> "$LOG_NAME"
	echo "ls -la /ssh/ssh_config 644" >> "$LOG_NAME"
	ls -la /ssh/ssh_config >> "$LOG_NAME" 2>&1
	echo ""  >> "$LOG_NAME"
	echo "ls -la /etc/rsyslog.conf 400" >> "$LOG_NAME"
	ls -la /etc/rsyslog.conf >> "$LOG_NAME" 2>&1
	echo ""  >> "$LOG_NAME"
	echo "ls -la /etc/audit/auditd.conf 644" >> "$LOG_NAME"
	ls -la /etc/audit/auditd.conf >> "$LOG_NAME" 2>&1
	echo ""  >> "$LOG_NAME"
else
	echo "[文件均合规]" >> "$LOG_NAME"
	echo ""  >> "$LOG_NAME"
fi
echo "[ok]">> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"


# 2.2 实现操作系统和数据库系统特权用户的权限分离
echo "2.2实现操作系统和数据库系统特权用户的权限分离" >> "$LOG_NAME"
echo "$(tput setaf 1)[*******人工测试查看*******]" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 2.3 限制默认账号权限
echo "2.3.限制默认账号权限" >> "$LOG_NAME"
echo "要求：应重命名系统默认账户（可选）；修改默认账户的默认口令。" >> "$LOG_NAME"
echo "$(tput setaf 1)[*******人工测试查看*******]" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 2.4 删除多余的、过期的帐户
echo "2.4 删除多余的、过期的帐户" >> "$LOG_NAME"
# 检查/etc/passwd
passwd_bash=`cat /etc/passwd | grep bash`
# 检查用户
user_1=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep Daemon`
user_2=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep Bin`
user_3=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep Sys`
user_4=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep Adm`
user_5=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep Uucp`
user_6=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep Nuucp`
user_7=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep Lpd`
user_8=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep Imnadm`
user_9=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep Ldap`
user_10=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep Lp`
user_11=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep Snapp`
user_12=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep invscout`
user_13=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep sync`
user_14=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep shutdown`
user_15=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep halt`
user_16=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep news`
user_17=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep operator`
user_18=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep games`
user_19=`cat /etc/passwd | grep -v ^# | grep -v ^$ | grep gopher`
array_user=($user_1 $user_2 $user_3 $user_4 $user_5 $user_6 $user_7 $user_8 $user_9 $user_10 $user_11 $user_12 $user_13 $user_14 $user_15 $user_16 $user_17 $user_18 $user_19)
if [ "$passwd_bash" != "" ]
then
    echo "详情请看日志，包括Daemon、Bin、Sys、Adm、Uucp、Nuucp、Lpd、Imnadm、Ldap、Lp、Snapp、invscout、sync、shutdown、halt、news、operator、games、gopher" >> "$LOG_NAME"
    echo "cat /etc/passwd | grep bash" >> "$LOG_NAME"
    cat /etc/passwd | grep bash >> "$LOG_NAME" 2>&1
    echo ""  >> "$LOG_NAME"
fi
if [ "$user_1" != "" ] || [ "$user_2" != "" ] || [ "$user_3" != "" ] || [ "$user_4" != "" ] || [ "$user_5" != "" ] || [ "$user_6" != "" ] || [ "$user_7" != "" ] || [ "$user_8" != "" ] || [ "$user_9" != "" ] || [ "$user_10" != "" ] || [ "$user_11" != "" ] || [ "$user_12" != "" ] || [ "$user_13" != "" ] || [ "$user_14" != "" ] || [ "$user_15" != "" ] || [ "$user_16" != "" ] || [ "$user_17" != "" ] || [ "$user_18" != "" ] || [ "$user_19" != "" ]
then
	for user in ${array_user[@]}
	do
		if [ $user != "" ]
		then
			echo -e $user >> "$LOG_NAME"  2>&1
		fi
	done
	echo "$(tput setaf 1)[---------未删除部分用户]"  >> "$LOG_NAME"
fi

echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 2.5 应禁止root用户使用FTP
echo "2.5.禁止root用户使用FTP" >> "$LOG_NAME"
# 检查/etc/ftpusers
ftpusers=`cat /etc/ftpusers | grep -v ^# | grep -v ^$ | grep root`
echo "ps aux | grep ftp" >> "$LOG_NAME" 2>&1
ps aux | grep ftp >> "$LOG_NAME" 2>&1
echo ""  >> "$LOG_NAME"
if [ -f /etc/ftpusers ]
then
    if [ "$ftpusers" = "" ]
    then
        echo "未禁止root用户使用FTP" >> "$LOG_NAME"
        echo "cat /etc/ftpusers | grep -v ^# | grep -v ^$" >> "$LOG_NAME"
        cat /etc/ftpusers | grep -v ^# | grep -v ^$ >> "$LOG_NAME" 2>&1
        echo ""  >> "$LOG_NAME"
    fi
else
    echo "不涉及ftp" >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
fi
echo "[OK]"  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"


# 2.7 禁止用户挂载移动设备
echo "2.7.禁止用户挂载移动设备" >> "$LOG_NAME"
# 检查/etc/security/console.perms
echo "详情请看日志,要求：#<console> ……		#<xconsole> ……" >> "$LOG_NAME"
echo "cat /etc/security/console.perms | grep -v ^# | grep -v ^$" >> "$LOG_NAME"
cat /etc/security/console.perms | grep -v ^# | grep -v ^$ >> "$LOG_NAME" 2>&1
echo ""  >> "$LOG_NAME"
echo "[$(tput setaf 1)[*******人工测试查看（日志）*******]"  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 2.8检查.rhosts、.exrc文件
echo "2.8.删除.rhosts、.exrc文件" >> "$LOG_NAME"
rhost=`find / -name '.rhosts'`
exrc=`find / -name '.exrc'`
if [ "$rhost" != "" ] || [ "$exrc" != "" ]
then
    echo "$(tput setaf 1)未删除.rhosts、.exrc文件" >> "$LOG_NAME"
    echo "find / -name '.rhosts'" >> "$LOG_NAME"
    find / -name '.rhosts' >> "$LOG_NAME"
    echo "find / -name '.exrc'" >> "$LOG_NAME"
    find / -name '.exrc' >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
else
	echo "[OK]"  >> "$LOG_NAME"
fi
echo ""  >> "$LOG_NAME"


# 3.安全审计
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "3.安全审计" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 3.1开启审计进程
echo "3.1 启用审计进程" >> "$LOG_NAME"
sys_log=`ps -ef | grep syslogd`
if [ "$sys_log" == "" ]
then
    echo "$(tput setaf 1)本地未启用日志功能，请咨询是否有第三方审计软件" >> "$LOG_NAME"
    echo "ps -ef|grep syslogd" >> "$LOG_NAME"
    ps -ef | grep syslogd >> "$LOG_NAME"
    echo ""  >> "$LOG_NAME"
else
	ps -ef | grep syslogd >> "$LOG_NAME"
	echo "[OK]"  >> "$LOG_NAME"
fi
echo ""  >> "$LOG_NAME"

# 3.2 审计记录配置
# 检查/etc/rsyslog.conf
echo "3.2 审计记录配置" >> "$LOG_NAME"
echo "cat /etc/rsyslog.conf | grep -v ^# | grep -v ^$" >> "$LOG_NAME"
cat /etc/rsyslog.conf | grep -v ^# | grep -v ^$ >> "$LOG_NAME" 2>&1
echo ""  >> "$LOG_NAME"
# 检查/etc/audit/auditd.conf
echo "cat /etc/audit/auditd.conf | grep -v ^# | grep -v ^$" >> "$LOG_NAME"
cat /etc/audit/auditd.conf | grep -v ^# | grep -v ^$ >> "$LOG_NAME" 2>&1
echo ""  >> "$LOG_NAME"
# 检查/etc/audit/audit.rules
echo "cat /etc/audit/audit.rules | grep -v ^# | grep -v ^$ | grep '\-w'" >> "$LOG_NAME" 
cat /etc/audit/audit.rules | grep -v ^# | grep -v ^$ | grep '\-w' >> "$LOG_NAME" 2>&1
echo "[$(tput setaf 1)[*******人工测试查看（日志）*******]"  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 3.3 保护审计记录
echo "3.3 保护审计记录" >> "$LOG_NAME"
# 检查rsyslog.conf文件权限
rsyslog=`ls -la /etc/rsyslog.conf | awk '{print $1}' | awk -F"." '{print $1}'`
if [ "$rsyslog" != "-r--------" ]
then
	echo "rsyslog.conf文件权限不合规" >> "$LOG_NAME"
	echo "ls -la /etc/rsyslog.conf 400" >> "$LOG_NAME"
    ls -la /etc/rsyslog.conf >> "$LOG_NAME" 2>&1
    echo ""  >> "$LOG_NAME"
else
	echo "[rsyslog.conf文件权限合规]" >> "$LOG_NAME"
	echo "ls -la /etc/rsyslog.conf 400" >> "$LOG_NAME"
    ls -la /etc/rsyslog.conf >> "$LOG_NAME" 2>&1
    echo ""  >> "$LOG_NAME"
fi

# 检查日志权限
echo "stat -c %a /var/log/messages<=644" >> "$LOG_NAME"
stat -c %a /etc/passwd >> "$LOG_NAME" 2>&1
echo ""  >> "$LOG_NAME"
echo "stat -c %a /var/log/secure<=644" >> "$LOG_NAME"
stat -c %a /etc/group >> "$LOG_NAME" 2>&1
echo ""  >> "$LOG_NAME"
echo "stat -c %a /var/log/maillog<=644" >> "$LOG_NAME"
stat -c %a /var/log/maillog >> "$LOG_NAME" 2>&1
echo ""  >> "$LOG_NAME"
echo "stat -c %a /var/log/cron<=644" >> "$LOG_NAME"
stat -c %a /var/log/cron >> "$LOG_NAME" 2>&1
echo ""  >> "$LOG_NAME"
echo "stat -c %a /var/log/spooler<=644" >> "$LOG_NAME"
stat -c %a /var/log/spooler >> "$LOG_NAME" 2>&1
echo ""  >> "$LOG_NAME"
echo "stat -c %a /var/log/boot.log<=644" >> "$LOG_NAME"
stat -c %a /var/log/boot.log >> "$LOG_NAME" 2>&1
echo ""  >> "$LOG_NAME"
echo "stat -c %a /var/log/btmp<=644" >> "$LOG_NAME"
stat -c %a /var/log/btmp >> "$LOG_NAME" 2>&1
echo ""  >> "$LOG_NAME"
echo "stat -c %a /var/log/wtmp<=644" >> "$LOG_NAME"
stat -c %a /var/log/wtmp >> "$LOG_NAME" 2>&1
echo ""  >> "$LOG_NAME"
echo "stat -c %a /var/log/lastlog<=644" >> "$LOG_NAME"
stat -c %a /var/log/lastlog >> "$LOG_NAME" 2>&1
echo ""  >> "$LOG_NAME"
echo "$(tput setaf 1)详情请看日志[*******人工测试查看*******]" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 3.4 审计日志保存配置(6个月以上)
echo "3.4 审计日志保存配置(6个月以上)" >> "$LOG_NAME"
# 检查/etc/logrotate.conf
echo "cat /etc/logrotate.conf | grep -v ^# | grep -v ^$" >> "$LOG_NAME"
cat /etc/logrotate.conf | grep -v ^# | grep -v ^$ >> "$LOG_NAME" 2>&1
echo "$(tput setaf 1)详情请看日志[*******人工测试查看*******]" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"


# 4.入侵防范
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "4.入侵防范" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 4.1 最小安装的原则
echo "4.1 最小安装的原则" >> "$LOG_NAME"
echo "$(tput setaf 1)[*******人工测试查看*******]" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 4.2 终端接入方式配置
echo "4.2 终端接入方式配置" >> "$LOG_NAME"
echo "cat /etc/hosts.allow" >> "$LOG_NAME"
cat /etc/hosts.allow | grep -v ^# | grep -v ^$ >> "$LOG_NAME" 2>&1
echo "cat /etc/hosts.deny" >> "$LOG_NAME"
cat /etc/hosts.deny | grep -v ^# | grep -v ^$ >> "$LOG_NAME" 2>&1
echo "$(tput setaf 1)[*******人工测试查看（询问管理员接入方式）*******]" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 5.资源控制
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "5.资源控制" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 5.1 限制单个用户对系统资源的最大或最小使用限度
echo "5.1 限制单个用户对系统资源的最大或最小使用限度" >> "$LOG_NAME"
# 检查/etc/security/limits.conf
maxlogins=`cat /etc/security/limits.conf | grep -v ^# | grep -v ^$ | grep maxlogins | awk '$4>=5 && $4<=10'`
if [ "$maxlogins" == "" ]
	then
    echo "$(tput setaf 1)未限制单个用户对系统资源的最大或最小使用限度" >> "$LOG_NAME"
	cat /etc/security/limits.conf | grep -v ^# | grep -v ^$ | awk '$4>=5 && $4<=10' >> "$LOG_NAME" 2>&1
    echo ""  >> "$LOG_NAME"
else
	echo "[OK]"  >> "$LOG_NAME"
fi
echo ""  >> "$LOG_NAME"

# 6.数据备份
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "6.数据备份" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
# 6.1重要服务器应具备热备冗余功能
echo "6.1重要服务器应具备热备冗余功能" >> "$LOG_NAME"
echo "$(tput setaf 1)[*******人工测试查看（询问管理员）*******]" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"