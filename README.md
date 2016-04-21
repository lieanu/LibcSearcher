Search libc function offset
---------------------------

1. 简介
=======

这是针对CTF比赛所做的小工具，在泄露了Libc中的某一个函数地址后，常常为不知道对方所使用的操作系统及libc的版本而苦恼，常规方法就是挨个把常见的Libc.so从系统里拿出来，与泄露的地址对比一下最后12位。

为了不在这一块浪费太多生命，写了几行代码，方便以后重用。

这里用了[libc-database](https://github.com/niklasb/libc-database)的数据库。

2. 使用
=======

`git clone https://github.com/lieanu/libc.git`


```python
from libc import *
obj = libc("fgets", "7ff39014bd90") #第二个参数，为已泄露的实际地址，字符串或int均可

obj.dump("system")        #system 偏移
obj.dump("str_bin_sh")    #/bin/sh 偏移
```

3.其它
======

水平一般，代码很烂，如有bug，欢迎吐槽。

欢迎贡献不同linux发行版的libc信息。
