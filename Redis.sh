#!/bin/bash
clear
echo ""
echo " ____________________________________________________________________ "
echo "|                                                                    |"
echo "|          Local Information gather Script for Redis                 |"
echo "|                                                                    |"
echo "|____________________________________________________________________|"
echo ""
echo ""

LOG_NAME="Local-Information_Redis_"`date +"%Y-%m-%d"`".log"

echo "" > "$LOG_NAME"
echo " ____________________________________________________________________ " >> "$LOG_NAME"
echo "|                                                                    |" >> "$LOG_NAME"
echo "|          Local Information gather Script for Redis                |" >> "$LOG_NAME"
echo "|                                                                    |" >> "$LOG_NAME"
echo "|____________________________________________________________________|" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"

IP=`ifconfig -a | grep inet|grep -v "127.0.0.1" | awk '{print $2}'| head -n 3`
echo "0.基本信息收集" >> "$LOG_NAME"
echo "ip: "$IP >> "$LOG_NAME"
echo "$REDIS_CONFIG_DIR" >> "$LOG_NAME"

# 1.身份鉴别
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "1.身份鉴别" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
# 1.1应提供专用的登录控制模块对登录用户进行身份标识和鉴别。
requirepass=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep requirepass | awk '{ print $2 }'`
echo "1.1应提供专用的登录控制模块对登录用户进行身份标识和鉴别。" >> "$LOG_NAME"
echo "cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep requirepass" >> "$LOG_NAME" 2>&1
cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep requirepass >> "$LOG_NAME" 2>&1
if [ "$requirepass" != "" ]
then
	echo "[ok]" >> "$LOG_NAME" 2>&1
else
	echo "[------redis数据库未设置密码------]" >> "$LOG_NAME" 2>&1
fi
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"

# 1.2应提供用户身份标识唯一和鉴别信息复杂度检查功能
echo "1.2应提供用户身份标识唯一和鉴别信息复杂度检查功能" >> "$LOG_NAME"
echo "cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep requirepass" >> "$LOG_NAME" 2>&1
cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep requirepass >> "$LOG_NAME" 2>&1
echo "[--------人工查看密码复杂度--------]" >> "$LOG_NAME" 2>&1
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"



# 2.访问控制
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "2.访问控制" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 2.1应禁止root用户启用redis
redis_root=`ps -ef | grep redis | awk '{ print $1 }'`
echo "2.1应禁止root用户启用redis" >> "$LOG_NAME"
echo "ps -ef | grep redis" >> "$LOG_NAME" >&1
ps -ef | grep redis | awk '{ print $1 }' >> "$LOG_NAME" >&1
if [ "redis_root" == "root" ]
then
	echo "【redis以root启动】" >> "$LOG_NAME" >&1
else
	echo "[ok]" >> "$LOG_NAME" >&1
fi
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"


# 2.2应修改默认口令
echo "2.2应修改默认口令" >> "$LOG_NAME"
echo "cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep requirepass" >> "$LOG_NAME" 2>&1
cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep requirepass >> "$LOG_NAME" 2>&1
if [ "$requirepass" != "foobared" ]
then
	echo "[ok]" >> "$LOG_NAME" 2>&1
else
	echo "[----------redis未修改默认口令----------]" >> "$LOG_NAME" 2>&1
fi
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"


# 2.3应严格控制数据库目录的访问权限
redis_=`stat -c %a /etc/redis`
echo "2.3应严格控制中间件目录的访问权限" >> "$LOG_NAME"
echo "stat -c %a /etc/redis<=755" >> "$LOG_NAME" 2>&1
stat -c %a /etc/redis >> "$LOG_NAME" 2>&1
if [ "$redis_" != "755" ]
then
	echo "[----redis数据库目录的访问权限不符合----]" >> "$LOG_NAME" 2>&1
else
	echo "[ok]"  >> "$LOG_NAME" 2>&1
fi
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"



# 2.4应严格限制配置文件和日志文件的访问权限
redis_conf=`stat -c %a /etc/redis/redis.conf`
echo "2.4应严格限制配置文件和日志文件的访问权限" >> "$LOG_NAME"
echo "stat -c %a /etc/redis/redis.conf<=640" >> "$LOG_NAME"
stat -c %a /etc/redis/redis.conf >> "$LOG_NAME" 2>&1
if [ "$redis_conf" != "640" ]
then
	echo "[----redis数据库配置文件的访问权限不符合----]" >> "$LOG_NAME" 2>&1
else
	echo "[ok]"  >> "$LOG_NAME" 2>&1
fi
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"


# 3.安全审计
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "3.安全审计" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 3.1应提供覆盖到每个用户的安全审计功能
echo "3.1应提供覆盖到每个用户的安全审计功能" >> "$LOG_NAME"
echo "cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep loglevel" >> "$LOG_NAME" 2>&1
cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep loglevel >> "$LOG_NAME" 2>&1
echo "" >> "$LOG_NAME"

echo "cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep appendfsync" >> "$LOG_NAME" 2>&1
cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep appendfsync >> "$LOG_NAME" 2>&1
echo "" >> "$LOG_NAME"

echo "cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep appendonly" >> "$LOG_NAME" 2>&1
cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep appendonly >> "$LOG_NAME" 2>&1
echo "[--------检查配置--------]" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"


# 3.2审计日志保留时间满足6个月以上
echo "3.2审计日志保留时间满足6个月以上" >> "$LOG_NAME"
echo "cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep logfile" >> "$LOG_NAME" 2>&1
cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep logfile >> "$LOG_NAME" 2>&1
logfile=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep logfile| awk '{ print $2 }'`
echo "stat -c %a $logfile=640" >> "$LOG_NAME" 2>&1
stat -c %a "$logfile" >> "$LOG_NAME" 2>&1
echo "" >> "$LOG_NAME"

echo "cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep appendfilename" >> "$LOG_NAME" 2>&1
cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep appendfilename >> "$LOG_NAME" 2>&1
appendfilename=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep logfile| awk '{ print $2 }'`
echo "stat -c %a $appendfilename=640" >> "$LOG_NAME" 2>&1
stat -c %a "$appendfilename" >> "$LOG_NAME" 2>&1
echo "" >> "$LOG_NAME"

echo "[--------检查配置--------]" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"

# 4.资源控制
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "4.资源控制" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 4.1配置会话空闲超时锁定功能
timeout=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep timeout`
echo "4.1配置会话空闲超时锁定功能" >> "$LOG_NAME"
echo "cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep timeout" >> "$LOG_NAME" 2>&1
cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep timeout >> "$LOG_NAME" 2>&1
if [ "$timeout" != "" ]
then
	echo "[ok]" >> "$LOG_NAME" 2>&1
else
	echo "[----------redis未配置空闲超时锁定功能---------]" >> "$LOG_NAME" 2>&1
fi
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"

# 5.入侵防护
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "5.入侵防护" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"
echo "######################################################################" >> "$LOG_NAME"
echo ""  >> "$LOG_NAME"

# 5.1修改默认端口port 6379
port=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep port | awk '{ print $2 }'`
echo "5.1修改默认端口port 6379" >> "$LOG_NAME"
echo "cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep port" >> "$LOG_NAME" 2>&1
cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep port >> "$LOG_NAME" 2>&1
if [ "$port" == "6379" ]
then
	echo "[----------redis未修改默认端口---------]" >> "$LOG_NAME" 2>&1
else
	echo "[ok]" >> "$LOG_NAME" 2>&1
fi
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"


# 5.2应修改错误文件信息,防止信息泄漏
echo "5.2应修改错误文件信息,防止信息泄漏" >> "$LOG_NAME"
rename_command_2=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command FLUSHDB"`
rename_command_3=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command FLUSHALL"`
rename_command_4=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command KEYS"`
rename_command_5=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command PEXPIRE"`
rename_command_6=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command DEL"`
rename_command_7=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command CONFIG"`
rename_command_8=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command SHUTDOWN"`
rename_command_9=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command BGREWRITEAOF"`
rename_command_10=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command BGSAVE"`
rename_command_11=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command SAVE"`
rename_command_12=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command SPOP"`
rename_command_13=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command SREM"`
rename_command_14=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command RENAME"`
rename_command_15=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command DEBUG"`
rename_command_16=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command EVAL"`
if [ "$rename_command_2" == ""] || [ "$rename_command_3" == ""] || [ "$rename_command_4" == ""] || [ "$rename_command_5" == ""] || [ "$rename_command_6" == ""] || [ "$rename_command_7" == ""] || [ "$rename_command_8" == ""] || [ "$rename_command_9" == ""] || [ "$rename_command_10" == ""] || [ "$rename_command_11" == ""] || [ "$rename_command_12" == ""] || [ "$rename_command_13" == ""] || [ "$rename_command_14" == ""] || [ "$rename_command_15" == ""] || [ "$rename_command_16" == ""]
then
	echo "[------缺少修改命令------]" >> "$LOG_NAME"
fi
echo 'cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command FLUSHDB"'  >> "$LOG_NAME" 2>&1
echo "$rename_command_2" >> "$LOG_NAME" 2>&1
echo 'cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command FLUSHALL"'  >> "$LOG_NAME" 2>&1
echo "$rename_command_3" >> "$LOG_NAME" 2>&1
echo 'cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command KEYS"'  >> "$LOG_NAME" 2>&1
echo "$rename_command_4" >> "$LOG_NAME" 2>&1
echo 'cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command PEXPIRE"'  >> "$LOG_NAME" 2>&1
echo "$rename_command_5" >> "$LOG_NAME" 2>&1
echo 'cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command DEL"'  >> "$LOG_NAME" 2>&1
echo "$rename_command_6" >> "$LOG_NAME" 2>&1
echo 'cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command CONFIG"'  >> "$LOG_NAME" 2>&1
echo "$rename_command_7" >> "$LOG_NAME" 2>&1
echo 'cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command SHUTDOWN"'  >> "$LOG_NAME" 2>&1
echo "$rename_command_8" >> "$LOG_NAME" 2>&1
echo 'cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command BGREWRITEAOF"'  >> "$LOG_NAME" 2>&1
echo "$rename_command_9" >> "$LOG_NAME" 2>&1
echo 'cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command BGSAVE"'  >> "$LOG_NAME" 2>&1
echo "$rename_command_10" >> "$LOG_NAME" 2>&1
echo 'cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command SAVE"'  >> "$LOG_NAME" 2>&1
echo "$rename_command_11" >> "$LOG_NAME" 2>&1
echo 'cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command SPOP"'  >> "$LOG_NAME" 2>&1
echo "$rename_command_12" >> "$LOG_NAME" 2>&1
echo 'cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command SREM"'  >> "$LOG_NAME" 2>&1
echo "$rename_command_13" >> "$LOG_NAME" 2>&1
echo 'cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command RENAME"'  >> "$LOG_NAME" 2>&1
echo "$rename_command_14" >> "$LOG_NAME" 2>&1
echo 'cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command DEBUG"'  >> "$LOG_NAME" 2>&1
echo "$rename_command_15" >> "$LOG_NAME" 2>&1
echo 'cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep "rename-command EVAL"'  >> "$LOG_NAME" 2>&1
echo "$rename_command_1" >> "$LOG_NAME" 2>&1
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"



# 5.3限制应用服务器Threads数量
maxclients=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep maxclients`
echo "5.3限制应用服务器Threads数量" >> "$LOG_NAME"
echo "cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep maxclients" >> "$LOG_NAME" 2>&1
cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep maxclients >> "$LOG_NAME" 2>&1
if [ "$maxclients" != "" ]
then
	echo "[ok]" >> "$LOG_NAME" 2>&1
else
	echo "[----------redis未配置Threads数量---------]" >> "$LOG_NAME" 2>&1
fi
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"


# 5.4应对redis管理后台操作进行登陆源限制
bind=`cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep bind`
echo "5.4应对redis管理后台操作进行登陆源限制" >> "$LOG_NAME"
echo "cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep bind" >> "$LOG_NAME" 2>&1
cat /etc/redis/redis.conf | grep -v ^# | grep -v ^$ | grep bind >> "$LOG_NAME" 2>&1
if [ "$bind" != "" ]
then
	echo "[ok]" >> "$LOG_NAME" 2>&1
else
	echo "[----------redis未进行登陆源限制---------]" >> "$LOG_NAME" 2>&1
fi
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"


# 5.5及时更新redis补丁7.0.14
echo "5.5及时更新redis补丁7.0.14" >> "$LOG_NAME"
echo "redis-server -v" "$LOG_NAME"  2>&1
redis-server -v >> "$LOG_NAME"  2>&1
echo "[-----人工查看redis版本-----]"
echo "" >> "$LOG_NAME"
echo "" >> "$LOG_NAME"
