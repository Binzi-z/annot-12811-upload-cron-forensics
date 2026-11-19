================ 取证摘要 ================
结论：真实入侵（web shell upload -> cron 持久化 -> 外联 C2），涉事账号 www-data；运维改权限属误改前置条件，已排除。

攻击时间线（每条均含 文件:行号 物证）：
  [背景] stage0 upload_dir_executable_context | (no artifact in evidence pack) | 上传目录可执行是攻击得以发生的前置条件，但属运维误改而非入侵行为，排除出异常清单
  [恶意] stage1 web_shell_upload_and_landing | evidence/auth_excerpt.log:29 | HTTP POST 上传 shell.php，web 应用接收上传返回 200，入口向量为 web shell upload
  [恶意] stage1 web_shell_upload_and_landing | evidence/files.txt:2 | 上传目录落地 webshell /var/www/html/uploads/shell.php，属主 www-data、权限 644，与 HTTP 上传文件名一致
  [恶意] stage2 web_shell_execution | evidence/auth_excerpt.log:30 | 访问 /uploads/shell.php 并带 cmd=id 参数，webshell 被实际触发执行（RCE 确认）
  [恶意] stage2 web_shell_execution | evidence/bash_history.txt:58 | 攻击者（webshell 上下文）切换进入上传目录，为落地脚本做准备
  [恶意] stage2 web_shell_execution | evidence/bash_history.txt:60 | 在上传目录写入 webshell shell.php，内含 system($_GET[cmd]) 一句话命令执行
  [恶意] stage3 cron_persistence | evidence/bash_history.txt:62 | 编辑当前账号（www-data）的 crontab，建立持久化
  [恶意] stage3 cron_persistence | evidence/files.txt:3 | www-data 个人 crontab 文件被改写（权限 600），对应 crontab -e 动作
  [恶意] stage4 outbound_c2_connection | evidence/crontab.txt:3 | 恶意计划任务：*/5 * * * * 周期性下载远程脚本并管道交给 bash 执行（C2: 203.0.113.66），既是持久化也是外联来源

恶意事件 8 条；已排除正常动作 59 条（含 git pull / systemctl status nginx 等日常命令、ops 内网 SSH 登录、healthcheck.sh 巡检任务）。
证据分级：同源内部排序靠时间戳；跨源关联全部有内容物证（文件名/参数/属主/URL 互证）；
外联实际连接无流量日志，仅由 crontab.txt:3 的计划命令推断。
==========================================
