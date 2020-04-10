```
pip._vendor.urllib3.exceptions.ReadTimeoutError: HTTPSConnectionPool(host='files.pythonhosted.org', port=443): Read timed out.
遇到ReadTimeout错误，造成这个问题的原因就是网速问题。
pip --default-timeout=1000 install -U 模块名
```

