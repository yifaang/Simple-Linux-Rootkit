# 一个简单的Linux Kernel Module
简单的rootkit程序，接触不久 也许并不能在实战中造成什么危害，但是欺负一些不太懂rootkit的安服仔仔合适不过了
## 1. Rootkit 功能性
### 1.1 隐藏`lsmod`显示内核模块
程序通过删除THIS_MODULE中的链表，通过lsmod指令将不会显示内核中插入了本模块，常规方式无法卸载本模块
### 1.2 隐藏`netstat`显示
隐藏了netstat指令显示活动网络——测试中.... 依然存在部分问题 也许我会更新这个功能？？？
### 1.3 隐藏`ps`进程隐藏
通过hook `getdent64`系统调用，hook隐藏了进程显示
### 1.4 隐藏`ls`文件隐藏
通过hook `getdent64`系统调用，隐藏了`evil.php` `EVILBACKDOOR`这两个文件 方便隐藏php一句话木马 或者 驱动文件 方面加载SetSuperUser功能，但是目前来看，还没有写到这个功能
### 1.5 禁止`kill`发送结束信号给保护进程
通过hook`kill`系统调用，使发送的信号15&9信号失效，程序不死
## 2. 截图展示
### 2.1 文件目录隐藏

编译完成之后直接插入内核即可完成文件名隐藏，我只隐藏了 `evil.php` `EVILBACKDOOR`这两个文件一个作为php木马，一个作为隐藏驱动文件，为后续setsuperuser做准备，当然....有别的办法

![image-20231206234952471](https://raw.githubusercontent.com/yifaang/picture/main/test/image-20231206234952471.png)

### 2.2 隐藏ps命令进程

通过向需要隐藏的进程发送64号消息，注册保护进程，同时隐藏内核模块

如下情况，程序正常执行，ps命令无法找到

![image-20231206235544391](https://raw.githubusercontent.com/yifaang/picture/main/test/image-20231206235544391.png)

### 2.3 lsmod命令隐藏内核模块

注册完成保护进程后，再次查看lsmod中的信息，已经无法找到插入的内核程序

![image-20231206235705634](https://raw.githubusercontent.com/yifaang/picture/main/test/image-20231206235705634.png)

### 2.4 不死进程

通过kill命令向程序发送结束信号，已经无法结束程序

![image-20231206235800857](https://raw.githubusercontent.com/yifaang/picture/main/test/image-20231206235800857.png)

### 2.5 netstat隐藏

隐藏之后无法看到远程连接的端口 打开的是因为4444在监听

![image-20231207000439956](https://raw.githubusercontent.com/yifaang/picture/main/test/image-20231207000439956.png)

## 3. 程序更新
程序大概率...？还会更新吧.... 
看我情况 毕竟接下来会向更深层次的rootkit进行学习，不出意外会填补目前的坑，Setsuperuser、Netstat彻底隐藏端口(不过看完完这个程序应该都会了吧？？？ 毕竟方法都差不多)