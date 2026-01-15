介绍：
在批量使用sqlmap扫资产时，利用该脚本同时使用-m和-r参数的功能


usage:
python .\sqlmap_bulk_host.py -m .\url.txt -r .\request.txt --sqlmap "D:\desk\tool\sqlmap\sqlmap-master\sqlmap.py"  -- --batch --level=3

疑似存在sql注入的资产保存在当前命令的result.txt文件下
