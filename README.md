usage:

快速判断数据库类型

```
python .\sqlmap_bulk_host.py -m .\url.txt -r .\request.txt --sqlmap "D:\desk\tool\sqlmap\sqlmap-master\sqlmap.py" -- --batch --fingerprint --banner --technique=BE --level=1 --risk=1 --timeout=10 --proxy="http://127.0.0.1:8081"
```

 介绍：
在批量使用sqlmap扫资产时，利用该脚本同时使用-m和-r参数的功能