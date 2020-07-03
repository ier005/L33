---
title: WP for ctfzone-rand
categories: [Security]
tags: [ctf, php, pseudo-random]
date: 2017-07-23T00:00:00+08:00
---



这道题目主要考察**伪随机数**的安全问题。事实上，在许多web应用中都使用了随机数，但随机数的使用在很多时候并不安全，存在诸如伪随机、种子泄露等问题。

## PHP源码分析

题目给出的php源码如下：

``` php
<?php
include('config.php');
session_set_cookie_params(300);
session_start();
echo rand();
if (isset($_GET['go'])) {
    $_SESSION['rand'] = array();
    $i = 5;
    $d = '';
    while($i--){
        $r = (string)rand();
        $_SESSION['rand'][] = $r;
        $d .= $r;
    }
    echo md5($d);
    $_SESSION['secret'] = md5($d);
} else if (isset($_GET['check'])) {
    if ($_GET['check'] === $_SESSION['rand']) {
        echo $flag;
    } else {
        echo 'die';
        session_destroy();
    }
} else {
    show_source(__FILE__);
}

```

每次访问页面都会输出一个rand()值。

- 当传入了参数`go`之后，会产生5个随机数，存在Array型变量`$_SESSION['rand']`中，然后输出五个随机数组成的字符串的md5哈希值
- 当传入了参数`check`之后，会将`check`的值与`$_SESSION['rand']`的值进行比较，相等则给出FLAG
- 其他情况则给出文件的源码

无疑，输出的md5哈希值对我们来说没有任何作用，无法通过哈希值来进行逆推。

题目的思路很明显，通过给出的已产生的随机数，来推导接下来五次产生的随机数。

此处需要注意的是php的语法问题，最初以为`$_SESSION['rand'][] = $r`语句的左值全为`$_SESSION['rand'][0]`，此赋值语句会对同一对象重复赋值。但事实证明，此语句实际上的效果是进行了**append**的操作！
也就是说`$_SESSION['rand'][] = $r`语句执行五次后，得到了一个有五个元素的数组，元素的值按照之前赋值的顺序依次存储。

## 解题历程

### 伪随机数的不安全性质

有[文章](https://forrestx386.github.io/2017/03/27/%E5%85%B3%E4%BA%8EPHP%E4%B8%AD%E4%BC%AA%E9%9A%8F%E6%9C%BA%E6%95%B0%E5%AE%89%E5%85%A8%E6%80%A7%E5%88%86%E6%9E%90/)（同时给出了证明`mt_rand()`函数不安全的例子）指出，rand()函数来产生随机数，事实上是极其不安全的，可以通过以往产生的随机数来推导出下一个要产生的随机数。

有如下公式给出了`rand()`产生随机数的推导公式，此公式的成功率为50%。

	random[i] = random[i-3] + random[i-31]
题目给出了每次产生的随机数值，所以可以构造脚本来获取前32个随机数的值，传入`go`参数后，自己推导后五个随机数的数值，之后将其作为`check`参数的值，进行提交。由于上述公式成功率不为100%，所以需要进行多次尝试。

> rand()函数是可以指定产生的随机数的范围的，在未指定的情况下，默认范围为0~2147483646，所以进行推导时，每次的和应该模`2147483647`取余。

### HTTP参数传入数组

HTTP是可以通过`GET`或者`POST`的请求来传递数组的，两种传递方式其实一样。

	?info[name]=huyongde&info[age]=20
通过上面的方式进行参数传递，则在PHP后端`$_GET['info']`或者`$_POST['info']` 是一个数组：

	array('name'=>'huyongde', 'age'=>20);
其中，参数传递时的中括号内可以为空。

### 最终脚本

最终python脚本如下：

``` python
#!/usr/bin/python

import requests

def force():
	r = requests.session()
	url = "http://.../?"

	rand = []
	for i in range(31):
		content = r.get(url).text
		index = content.index('<code>')
		rand.append(int(content[:index]))
#		print rand

	content = r.get(url + 'go=').text
	rand.append(int(content[:-32]))

	for i in range(32, 37):
		rand.append((rand[i - 3] + rand[i - 31]) % 2147483647)
		url += ('check[]=' + str(rand[-1]))
		if i != 36:
			url += '&'

	content = r.get(url).text;
	print content
	if 'die' not in content:
		exit(0)

while True:
	force()
```

### 获取FLAG

获得Flag如下：

	0CTF{rand_is_rand?_maybe_not}
注意开始的字符0，不要将其当作随机数的个位数。。。

## 总结

在php中，两种产生随机数的方法都是不安全的。一个是`rand()`，另一个是`mt_rand()`，他们都只保证了随机数的均匀性，但具有**可重现**和**可预测**的不安全性质。如果随机数的种子泄露，则使用相同的种子得到的随机数序列是完全相同的，是为可重现性；即使没有随机数的种子，仍然可以通过以往的随机数值，来推导出下一个即将产生的随机数值。

- 对于`rand()`来说，可以通过以往的随机数序列推导出即将要产生的随机数，随机数序列`random[i] = random[i-3] + random[i-31]`，此公式成功率能达到50%。
- 对于`mt_rand()`来说，则可以通过产生的一个随机数进行推导出可能的种子，进而能够得到整个随机序列。有程序[php_mt_seed](http://download.openwall.net/pub/projects/php_mt_seed/)实现了此功能。