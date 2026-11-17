# 上传目录异常后的持久化链路取证

上传目录被运维临时改成可执行，几天后出现可疑的定时任务与外部连接，需要判断是运维误改还是真的被打进去。

```
evidence/bash_history.txt   带时间戳的命令历史
evidence/auth_excerpt.log   认证日志片段
evidence/files.txt          可疑文件的落地时间与属主
labels.json                 入口向量 / 持久化方式 / 涉及账号
triage.py                   现有分诊脚本（只做关键词匹配）
tests/                      骨架测试
```

## Run

```bash
python -m pytest tests -q
python triage.py evidence timeline.json
```

## 现状

`triage.py` 把命中 curl / wget / crontab 的行原样列出，不排序、不关联账号，
也不区分噪声命令。真正的入口向量与持久化手法需要人工从输出里翻。

## 标注

- 入口向量：`web shell upload`
- 持久化：`cron`
- 涉及账号：`www-data`

`bash_history.txt` 里另有若干日常命令，属于噪声，报出来算误报。
