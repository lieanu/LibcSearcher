Search libc function offset
---------------------------

1. 简介
=======

这是针对CTF比赛所做的小工具，在泄露了Libc中的某一个函数地址后，常常为不知道对方所使用的操作系统及libc的版本而苦恼，常规方法就是挨个把常见的Libc.so从系统里拿出来，与泄露的地址对比一下最后12位。

为了不在这一块浪费太多生命，写了几行代码，方便以后重用。

2. 使用
=======

`git clone https://github.com/lieanu/libc.git`

submodule `libc_binary`不是必须的。

```python
from libc import *
obj = libc("fgets", "7ff39014bd90") #第二个参数，为已泄露的实际地址，字符串或int均可

obj.system_address()        #system 地址
obj.system_offset()         #system 偏移
obj.base()                  #libc 基址
obj.address_by_name("puts") #返回puts函数地址
```

3. 完善
=======

现在阶段database里只包括了为数不多的几个常用版本，添加新的版本的libc.so的信息进去也非常简单

```
objdump -T your_libc.so.6 > OS版本_32or64bitOS_32or64bitLibc.db
```

将这个文件放到database里即可。

4.其它
======

水平一般，代码很烂，如有bug，欢迎吐槽。

欢迎贡献不同linux发行版的libc信息。
