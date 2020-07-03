---
title: WP for ctfzone-simple-heartbleed
categories: [Security]
tags: [ctf, buffer overflow]
date: 2017-07-23T00:00:00+08:00
---

这道题目实际上是一道hticon的题目，原本题目的名称叫做**leaking**，而ctfzone改名叫做**simple haertbleed**，这也是有原因的，因为这道题目跟OpenSSL的著名漏洞[Heartbleed](http://heartbleed.com/)有相似之处，是利用了**缓冲区溢出**的漏洞。

## 题目分析

题目直接给出了WEB服务器后端的源码，如下：

``` javascript
"use strict";

var randomstring = require("randomstring");
var express = require("express");
var {VM} = require("vm2");
var fs = require("fs");

var app = express();
var flag = require("./config.js").flag

app.get("/", function (req, res) {
    res.header("Content-Type", "text/plain");

    /*    Orange is so kind so he put the flag here. But if you can guess correctly :P    */
    eval("var flag_" + randomstring.generate(64) + " = \"flag{" + flag + "}\";")
    if (req.query.data && req.query.data.length <= 12) {
        var vm = new VM({
            timeout: 1000
        });
        console.log(req.query.data);
        res.send("eval ->" + vm.run(req.query.data));
    } else {
        res.send(fs.readFileSync(__filename).toString());
    }
});

app.listen(80, function () {
    console.log("listening on port 80!");
});
```

这才知道原来**JavaScript**还可以用作服务器的后端语言，这道题目的后台使用了Node.js的WEB框架[Express](http://expressjs.com/)，并且在题目中使用了运行不受信任代码代码的沙盒[VM2](https://github.com/patriksimek/vm2)。

看过源码之后，很容易就能看出，可以通过`data`参数使用`GET`方法来上传代码执行，目的是获取FLAG。但题目中给出了两个限制：

- 上传代码长度限制为12
- 在沙盒VM2中能够执行的语句相当有限，需要绕过VM2的限制获取FLAG



## 解题过程

### 绕过参数长度限制

代码对`data`参数进行了长度限制，不能超过12个字符。这可以通过传递数组参数来进行绕过（在这一点上似乎跟PHP有些不同，PHP的数组元素转换为字符串的时候，会得到`'Array'`的转换结果），这样判断的就不是字符串的长度，而是数组的长度，如下：

	?data[]=code.....

### 绕过沙盒限制

关于如何绕过沙盒的限制来获取FLAG，题目名称已经给出了提示。从题目源码中，看起来貌似正确的解题思路是破解`falg_randomstring.generate(64)`这一随机变量名，但实际上这只是一种误导而已。

纵然VM2的目的是提供了安全的沙盒环境，但可以在github上可以看到[ISSUE](https://github.com/patriksimek/vm2/issues/32)提到了绕过方式，但这些方法不能用到这一题目上。从题目的**Simple Heartbleed**可以得到提示，这是一个著名的OpenSSL的缓冲区溢出的漏洞，而Node.js是否也存在这种漏洞呢？答案是肯定的。

我们可以通过Node.js这一[缓冲区溢出](https://github.com/nodejs/node/issues/4660)漏洞来获取内存中的数据，在获取的二进制数据中，搜索我们想要的FLAG。

构造如下GET请求：

	http://...?data=new%20Buffer(10000)

会跳出一个下载，拿到10000字节的数据，通过strings命令，可以找到其中的字符串，其中就有FLAG：

	flag{h34rtbleed?}


