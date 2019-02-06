# Html Video Player 1.2.5 Stack Overflow 漏洞分析

> 第一次进行实际漏洞的分析，先从一个比较简单的栈溢出漏洞上手，顺便认识一下windows Pwn
>
> 跟着[M4x的教程](http://m4x.fun/post/html5-video-player-1.2.5-local-buffer-overflow-analysis/)走一发

经过对程序的检查，程序使用.net架构，可以用dnspy进行反编译分析，能够清晰的看到内部程序逻辑。

已经判断出来，溢出发生在进行注册时的账号和密码，可以通过keyword搜索定位到程序的对应位置，对溢出情况进行分析。

![](img/die.png)

在dnspy中通过关键字*keycode*和*username*进行查找，可以定位到关键函数位置

![](http://ww1.sinaimg.cn/large/006z37hrly1fzwu1erw9pj30oq04ewel.jpg)

根据其中的函数名称，可以基本确定，第一个调用的makeSureEngineInit()是一个初始化函数，保证后续操作正常进行，与我们的输入无关。funcDLLVerifyKeyCode函数传递了username和keycode，溢出应该发生在此处。

```c#
// Token: 0x06000244 RID: 580
[DllImport("KeyCodeDLL.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi, EntryPoint = "#1")]
private static extern int funcDLLVerifyKeyCode(string strUserName, string strKeyCode);
```

点击定位可以发现，这个函数是dll文件中的导出函数，在dnspy中无法进行分析，可以使用ida打开KeyCodeDLL.dll，dll文件去掉了符号表，无法直接找到对应的函数，但是通过查看Export导出表，可以查看此dll文件中到处函数名与对应的地址。

![](http://ww1.sinaimg.cn/large/006z37hrly1fzx3ln2lrhj30ig04zq2w.jpg)

虽然前两个的名字无法确定，但是可以基本确定，我们的目标函数就在其中，点击反编译得到伪代码，和dnspy中的函数结构进行比较，很容易完成对目标函数的匹配