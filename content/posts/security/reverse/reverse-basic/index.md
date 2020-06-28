---
title: 逆向工程基础
date: 2017-11-03T00:00:00+08:00
categories: [Security]
tags: [reverse]
---

> 文章内容参考来源：[CTF-All-In-One](https://www.gitbook.com/book/firmianay/ctf-all-in-one/details)

## 从源代码到可执行文件

以下面简单代码为例：

```c
//hello.c
#include <stdio.h>

void main(int argc, char **argv) {
    printf("hello world\n");
}
```

GCC在编译源码时，会直接生成一个可执行文件，但实际上这一过程可以具体分为四个步骤：**预处理（Preprocessing）、编译（Compilation）、汇编（Assembly）和链接（Linking）**。

只不过其中生成的临时文件并没有被保留下来，我们可以通过`-save-temps`参数来保留编译过程中生成的临时文件，并且通过`--verbose`指令来显示GCC的工作流程：

	$ gcc -save-temps hello.c --verbose
屏幕会输出很多信息，具体关注以下四条输出：

	/usr/lib/gcc/x86_64-linux-gnu/6/cc1 -E -quiet -v -imultiarch x86_64-linux-gnu hello.c -mtune=generic -march=x86-64 -fpch-preprocess -o hello.i
	/usr/lib/gcc/x86_64-linux-gnu/6/cc1 -fpreprocessed hello.i -quiet -dumpbase hello.c -mtune=generic -march=x86-64 -auxbase hello -version -o hello.s
	as -v --64 -o hello.o hello.s
	/usr/lib/gcc/x86_64-linux-gnu/6/collect2 -plugin /usr/lib/gcc/x86_64-linux-gnu/6/liblto_plugin.so -plugin-opt=/usr/l...

cc1是 gcc 的编译器，将 `.c `文件编译为` .i`和`.s` 文件，as 是汇编器命令，将 `.s` 文件汇编成 `.o` 文件，collect2 是链接器命令，它是对命令 ld 的封装。

最终会生成以下文件：

	a.out  hello.i  hello.o  hello.s
共四个文件，对应上述编译过程中的四个步骤。

### 预处理

可以指定GCC参数来生成预处理后的文件：

	$ gcc -E hello.c -o hello.i

预处理过程生成的文件为`hello.i`，这仍然是一个C语言代码格式的文件，预处理过程主要处理源代码中以 “#” 开始的预编译指令：

- 将所有的 “#define” 删除，并且展开所有的宏定义。
- 处理所有条件预编译指令，如 “#if”、“#ifdef”、“#elif”、“#else”、“#endif”。
- 处理 “#include” 预编译指令，将被包含的文件插入到该预编译指令的位置。注意，该过程递归执行。
- 删除所有注释。
- 添加行号和文件名标号。
- 保留所有的 #pragma 编译器指令。


### 编译

可以通过指定GCC参数来生成编译后的文件：

	$ gcc -S hello.c -o hello.s

编译过程生成的是汇编代码文件，它把预处理完的文件进行一系列词法分析、语法分析、语义分析及优化后生成相应的汇编代码文件。

### 汇编

可以通过指定GCC参数来生成汇编器处理后文件：

	$ gcc -c hello.s -o hello.o
	or
	$ gcc -c hello.c -o hello.o
此时生成的文件为机器可以执行的指令，已经不是可读的文本文件，可以通过`objdump`命令一探究竟:

	$ objdump -d hello.o
	
	hello.o:     file format elf64-x86-64
	
	Disassembly of section .text:
	
	0000000000000000 <main>:
	   0:	55                   	push   %rbp
	   1:	48 89 e5             	mov    %rsp,%rbp
	   4:	48 83 ec 10          	sub    $0x10,%rsp
	   8:	89 7d fc             	mov    %edi,-0x4(%rbp)
	   b:	48 89 75 f0          	mov    %rsi,-0x10(%rbp)
	   f:	48 8d 3d 00 00 00 00 	lea    0x0(%rip),%rdi        # 16 <main+0x16>
	  16:	e8 00 00 00 00       	callq  1b <main+0x1b>
	  1b:	90                   	nop
	  1c:	c9                   	leaveq 
	  1d:	c3                   	retq   

### 链接

	$ gcc hello.o -o hello

目标文件需要链接一大堆文件才能得到最终的可执行文件。链接过程主要包括地址和空间分配（Address and Storage Allocation）、符号决议（Symbol Resolution）和重定向（Relocation）等。

链接又可以分为**静态链接**和**动态链接**，GCC默认使用动态链接：

	$ file hello
	hello: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Li...
可以看到`dynamically linked`字样。

## Linux ELF

Linux ELF（Executable Linkable Format）文件有三种类型：

- 可重定位文件（Relocatable file）
  - 包含了代码和数据，可以和其他目标文件链接生成一个可执行文件或共享目标文件。
- 可执行文件（Executable File）
  - 包含了可以直接执行的文件。
- 共享目标文件（Shared Object File）
  - 包含了用于链接的代码和数据，分两种情况。一种是链接器将其与其他的可重定位文件和共享目标文件链接起来，生产新的目标文件。另一种是动态链接器将多个共享目标文件与可执行文件结合，作为进程映像的一部分。

以下面的代码为例：

``` c
#include<stdio.h>

int global_init_var = 10;
int global_uninit_var;

void func(int sum) {
    printf("%d\n", sum);
}

void main(void) {
    static int local_static_init_var = 20;
    static int local_static_uninit_var;

    int local_init_val = 30;
    int local_uninit_var;

    func(global_init_var + local_init_val +
         local_static_init_var );
}
```

分别执行下列命令生成三个文件：

	$ gcc -m32 -c elfDemo.c -o elfDemo.o
	$ gcc -m32 elfDemo.c -o elfDemo.out
	$ gcc -m32 -static elfDemo.c -o elfDemo_static.out

使用 file 命令查看相应的文件格式：

	$ file elfDemo.o
	elfDemo.o: ELF 32-bit LSB relocatable, Intel 80386, version 1 (SYSV), not stripped
	
	$ file elfDemo.out 
	elfDemo.out: ELF 32-bit LSB shared object, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=50036015393a99344897cbf34099256c3793e172, not stripped
	
	$ file elfDemo_static.out 
	elfDemo_static.out: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 3.2.0, BuildID[sha1]=276c839c20b4c187e4b486cf96d82a90c40f4dae, not stripped


可以看到，上面三个文件即为ELF文件的三种类型。下面的图片描述了源文件中的代码和数据存放的位置（按照颜色对应）：

![ELF文件结构](./elfdemo.png)

在这个简化的 ELF 文件中，开头是一个“文件头”，之后分别是代码段、数据段和.bss段。程序源代码编译后，执行语句变成机器指令，保存在`.text`段；已初始化的全局变量和局部静态变量都保存在`.data`段；未初始化的全局变量和局部静态变量则放在`.bss`段。

把程序指令和程序数据分开存放有许多好处，从安全的角度讲，当程序被加载后，数据和指令分别被映射到两个虚拟区域。由于数据区域对于进程来说是可读写的，而指令区域对于进程来说是只读的，所以这两个虚存区域的权限可以被分别设置成可读写和只读，可以防止程序的指令被改写和利用。

## 动态链接

### 动态链接相关的环境变量

#### LD_PRELOAD

LD_PRELOAD 环境变量可以定义在程序运行前优先加载的动态链接库。这使得我们可以有选择性地加载不同动态链接库中的相同函数，优先加载的动态链接库中的函数可以覆盖原本链接库中的函数。这就可能导致劫持程序执行的安全问题。

下面是一个简单的密码验证程序：

``` c
//passwd.c
#include<stdio.h>
#include<string.h>
void main() {
    char passwd[] = "password";
    char str[128];

    scanf("%s", &str);
    if (!strcmp(passwd, str)) {
        printf("correct\n");
        return;
    }
    printf("invalid\n");
}
```

接下来我们可以构造一个恶意的动态链接库来重载 `strcmp()` 函数：

``` C
//hack.c
#include<stdio.h>                           
#include<stdio.h>
int strcmp(const char *s1, const char *s2) {
    printf("hacked\n");
    return 0;
}
```

通过下列指令来编译为动态链接库：

	gcc -shared -o hack.so hack.c

然后通过设置`LD_PRELOAD`参数就可以劫持程序运行，使本来的passwd程序执行我们自己定义的`strcmp`函数。

	$ LD_PRELOAD="./hack.so" ./passwd
	aaa
	hacked
	correct
#### LD_SHOW_AUXV

AUXV 是内核在执行 ELF 文件时传递给用户空间的信息，设置该环境变量可以显示这些信息。如：

	LD_SHOW_AUXV=1 ls
	AT_SYSINFO_EHDR: 0x7fff687d3000
	AT_HWCAP:        1fabfbff
	AT_PAGESZ:       4096
	AT_CLKTCK:       100
	AT_PHDR:         0x558c9ae1d040
	AT_PHENT:        56
	AT_PHNUM:        9
	AT_BASE:         0x7f9303848000
	AT_FLAGS:        0x0
	AT_ENTRY:        0x558c9ae22430
	AT_UID:          1000
	AT_EUID:         1000
	AT_GID:          1000
	AT_EGID:         1000
	AT_SECURE:       0
	AT_RANDOM:       0x7fff68779479
	AT_EXECFN:       /bin/ls
	AT_PLATFORM:     x86_64

## 内存管理

Linux 为每个进程维持了一个单独的虚拟地址空间，包括了 .text、.data、.bss、栈（stack）、堆（heap），共享库等内容。

32 位系统有 4GB 的地址空间，其中 0x08048000~0xbfffffff 是用户空间（3GB），0xc0000000~0xffffffff 是内核空间（１GB）。

![虚拟内存空间](./vm.png)

### 栈

栈是一个先入后出（First In Last Out(FILO)）的容器。用于存放函数返回地址及参数、临时变量和有关上下文的内容。程序在调用函数时，操作系统会自动通过压栈和弹栈完成保存函数现场等操作，不需要程序员手动干预。

栈由高地址向低地址增长，栈保存了一个函数调用所需要的维护信息，称为栈帧（Stack Frame）。在 x86 体系中，寄存器 `ebp` 指向堆栈帧的底部，`esp` 指向堆栈帧的顶部。压栈时栈顶地址减小，弹栈时栈顶地址增大。

- `PUSH`：用于压栈。将 `esp` 减 4，然后将其唯一操作数的内容写入到 `esp` 指向的内存地址
- `POP` ：用于弹栈。从 `esp` 指向的内存地址获得数据，将其加载到指令操作数（通常是一个寄存器）中，然后将 `esp` 加 4。

x86 体系下函数的调用总是这样的：

- 把所有或一部分参数压入栈中，如果有其他参数没有入栈，那么使用某些特定的寄存器传递。
- 把当前指令的下一条指令的地址压入栈中。
- 跳转到函数体执行。

其中第 2 步和第 3 步由指令 `call` 一起执行。跳转到函数体之后即开始执行函数，而 x86 函数体的开头是这样的：

- `push ebp`：把ebp压入栈中（old ebp）。
- `mov ebp, esp`：ebp=esp（这时ebp指向栈顶，而此时栈顶就是old ebp）
- [可选] `sub esp, XXX`：在栈上分配 XXX 字节的临时空间。
- [可选] `push XXX`：保存名为 XXX 的寄存器。

把ebp压入栈中，是为了在函数返回时恢复以前的ebp值，而压入寄存器的值，是为了保持某些寄存器在函数调用前后保存不变。函数返回时的操作与开头正好相反：

- [可选] `pop XXX`：恢复保存的寄存器。
- `mov esp, ebp`：恢复esp同时回收局部变量空间。
- `pop ebp`：恢复保存的ebp的值。
- `ret`：从栈中取得返回地址，并跳转到该位置。

栈帧对应的汇编代码：

```asm
PUSH ebp          ; 函数开始（使用ebp前先把已有值保存到栈中）
MOV ebp, esp      ; 保存当前esp到ebp中

...       　      ; 函数体
                　; 无论esp值如何变化，ebp都保持不变，可以安全访问函数的局部变量、参数
MOV esp, ebp    　; 将函数的其实地址返回到esp中
POP ebp       　  ; 函数返回前弹出保存在栈中的ebp值
RET              ; 函数返回并跳转
```

函数调用后栈的标准布局如下图（上面为高地址）：

![函数调用栈布局](./stack.png)

### 调用约定

函数调用约定是对函数调用时如何传递参数的一种约定。调用函数前要先把参数压入栈然后再传递给函数，并且调用结束后还需要将堆栈恢复原状。

一个调用约定大概有如下的内容：

- 函数参数的传递顺序和方式
- 栈的维护方式（收回传递参数所占用的栈空间）
- 名字修饰的策略

主要的函数调用约定如下（其中 cdecl 是 C 语言默认的调用约定）：


| 调用约定     | 函数调用后维护栈 | 参数传递                                     | 名字修饰             |
| -------- | -------- | ---------------------------------------- | ---------------- |
| cdecl    | 函数调用方    | 从右到左的顺序压参数入栈                             | 下划线＋函数名          |
| stdcall  | 函数本身     | 从右到左的顺序压参数入栈                             | 下划线＋函数名＋@＋参数的字节数 |
| fastcall | 函数本身     | 函数的第一个和第二个DWORD参数（或者尺寸更小的）通过ecx和edx传递，其他参数通过从右向左的顺序压栈 | @＋函数名＋@＋参数的字节数   |

除了参数的传递之外，函数与调用方还可以通过返回值进行交互。当返回值不大于 4 字节时，返回值存储在 eax 寄存器中，当返回值在 5~8 字节时，采用 eax 和 edx 结合的形式返回，其中 eax 存储低 4 字节， edx 存储高 4 字节。

### 堆

堆是用于存放除了栈里的东西之外所有其他东西的内存区域，有动态内存分配器负责维护。分配器将堆视为一组不同大小的块（block）的集合来维护，每个块就是一个连续的虚拟内存器片（chunk）。当使用 `malloc()` 和 `free()` 时就是在操作堆中的内存。对于堆来说，释放工作由程序员控制，容易产生内存泄露。

堆是向高地址扩展的数据结构，是不连续的内存区域。这是由于系统是用链表来存储的空闲内存地址的，而链表的遍历方向是由低地址向高地址。堆的大小受限于计算机系统中有效的虚拟内存。由此可见，堆获得的空间比较灵活，也比较大。

如果每次申请内存时都直接使用系统调用，会严重影响程序的性能。通常情况下，运行库先向操作系统“批发”一块较大的堆空间，然后“零售”给程序使用。当全部“售完”之后或者剩余空间不能满足程序的需求时，再根据情况向操作系统“进货”。

#### 进程堆管理

Linux 提供了两种堆空间分配的方式，一个是 `brk()` 系统调用，另一个是 `mmap()` 系统调用。可以使用 `man brk`、`man mmap` 查看。

##### brk()和sbrk()

`brk()` 的声明如下：

```c
#include <unistd.h>

int brk(void *addr);

void *sbrk(intptr_t increment);
```

参数 `*addr` 是进程数据段的结束地址，`brk()` 通过改变该地址来改变数据段的大小，当结束地址向高地址移动，进程内存空间增大，当结束地址向低地址移动，进程内存空间减小。`brk()`调用成功时返回 0，失败时返回 -1。 `sbrk()` 与 `brk()` 类似，但是参数 `increment` 表示增量，即增加或减少的空间大小，调用成功时返回增加后减小前数据段的结束地址，失败时返回 -1。

brk 指示堆结束地址，start_brk 指示堆开始地址。BSS segment 和 heap 之间有一段 Random brk offset，这是由于 ASLR 的作用，如果关闭了 ASLR，则 Random brk offset 为 0，堆结束地址和数据段开始地址重合。

##### mmap()和munmap()

`mmap()` 的声明如下：

```c
#include <sys/mman.h>

void *mmap(void *addr, size_t len, int prot, int flags,
    int fildes, off_t off);
```

`mmap()` 函数用于创建新的虚拟内存区域，并将对象映射到这些区域中，当它不将地址空间映射到某个文件时，我们称这块空间为匿名（Anonymous）空间，匿名空间可以用来作为堆空间。`mmap()` 函数要求内核创建一个从地址 `addr` 开始的新虚拟内存区域，并将文件描述符 `fildes` 指定的对象的一个连续的片（chunk）映射到这个新区域。连续的对象片大小为 `len` 字节，从距文件开始处偏移量为 `off` 字节的地方开始。`prot` 描述虚拟内存区域的访问权限位，`flags` 描述被映射对象类型的位组成。

`munmap()` 则用于删除虚拟内存区域：

```c
#include <sys/mman.h>

int munmap(void *addr, size_t len);
```

##### malloc()

通常情况下，我们不会直接使用 `brk()` 和 `mmap()` 来分配堆空间，C 标准库提供了一个叫做 `malloc` 的分配器，程序通过调用 `malloc()` 函数来从堆中分配块，声明如下：

```c
#include <stdlib.h>

void *malloc(size_t size);
void free(void *ptr);
void *calloc(size_t nmemb, size_t size);
void *realloc(void *ptr, size_t size);
```
