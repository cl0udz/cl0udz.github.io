# iOS下SSL PINNING的绕过
## 0x0 background
HTTPS在默认情况下，只能保证通信双方密钥交换完成，开始通信后的数据不被第三方窃取。如果攻击者发动中间人攻击，由于许多库函数的实现没有默认对服务器证书进行校验，攻击者仍然能够成功建立连接，捕获到通信内容。许多敏感APP，为了保证即便设备通信被完全劫持也不会泄露通信数据，会对服务器证书进行校验，当HTTPS协商过程中收到的证书不是由指定CA签发或者不是指定证书时，就拒绝本次通信。在iOS中，官方提供了相关的库函数和示例代码来帮助开发者完成这部分工作（0x4）。另外，iOS中应用较广的几个网络库也提供了对应的方法来对服务器证书进行验证（0x2和0x3）。

从信道攻击上来说，这样的防御方案已经几乎完全断绝了中间人攻击的可能性，除非中间人能够伪造/获取一份目标服务器的证书，攻击成本极大。
但如果我们还对设备本身有足够的权限，分析的目标是服务器的处理逻辑或者服务器与客户端的通信逻辑，仍然有办法对这种检测机制进行绕过。
## 0x1 绕过方法简单总结
首先需要确定目标APP使用的检测机制，因为除了官方库提供的方法以外，第三方网络库也会提供验证接口来对服务器的证书进行验证以避免中间人的攻击。
步骤如下：

1. hook带Trust字样的所有函数（如果目标APP的功能函数也含有大量的Trust，就需要自行摸索别的规则了）`python fast_hook_1.py '-[* *Trust*]'`
2. 触发，如果该APP没有全局部署检查，那么一般会在敏感操作部署。不过你既然已经知道需要绕过了，那你肯定知道哪里会做检查
3. 确定函数的参数和返回值，自行用frida修改好函数的参数和返回值。

实际上就是搜索目标APP空间内的所有检查函数，然后通过动态触发来定位具体的函数。最后通过自己构建一个可以通过检查的对象，来达到绕过的目的。

具体的绕过代码还是得具体情况具体分析，~~毕竟检查的函数大多都不是0/1返回式，需要自行构建对象来保证后期检查通过，所以需要对检查的代码本身由一定的了解，正向的代码在网上还是能找到一些的。~~虽然通常都是0/1返回式验证，但是有的用0表示通过，有的用1表示通过，不同库的实现也不同。

后面就我自己的经验，有几个具体的例子做介绍。

## 0x2 Alamofire
测试目标APP：洋钱罐（版本：3.4.0）

hook函数`-[NSURLProtectionSpace serverTrust]`，发现确实调用了。然后用frida-trace打印调用栈，看到几个奇长无比的函数。

```
called from:
0x1009de6b0 Alamofire!_T09Alamofire12TaskDelegateC10urlSessionySo10URLSessionC_So0fB0C4taskSo26URLAuthenticationChallengeC10didReceiveyAF04AuthI11DispositionO_So13URLCredentialCSgtc17completionHandlertF07_T0So10f3C24lim5OSo13N19CSgIyByy_AdGIxyx_TRAnQIyByy_Tf1nnncn_nTf4gggng_n
0x1009ca0ac Alamofire!_T09Alamofire15SessionDelegateC03urlB0ySo10URLSessionC_So0E4TaskC4taskSo26URLAuthenticationChallengeC10didReceiveyAF04AuthI11DispositionO_So13URLCredentialCSgtc17completionHandlertF07_T0So10e3C24lim5OSo13N19CSgIyByy_AdGIxyx_TRAnQIyByy_Tf1nnncn_nTf4gggng_n
0x1009c70bc Alamofire!_T09Alamofire15SessionDelegateC03urlB0ySo10URLSessionC_So0E4TaskC4taskSo26URLAuthenticationChallengeC10didReceiveyAF04AuthI11DispositionO_So13URLCredentialCSgtc17completionHandlertFTo
```

有Alamofire关键词，应该是用了这个库，库本身是Swift开发的，里面的具体方法可以用IDA打开dump出来的Alamofire的bin文件找到，调用serverTrust做验证的代码在调用栈最下层（上面第一个函数）的这个地方：

```c
            v63 = objc_msgSend(v7, "protectionSpace");
            v64 = (void *)objc_retainAutoreleasedReturnValue(v63);
            v65 = v64;
            v66 = objc_msgSend(v64, "serverTrust");
            v67 = objc_retainAutoreleasedReturnValue(v66);
            if ( v67 )
            {
              objc_release(v65);
              swift_unknownRetain(v67);
              swift_unknownRetain(v42);
              v68 = ((__int64 (__fastcall *)(__int64, __int64, __int64, __int64, __int64, __int64, __int64))_T09Alamofire17ServerTrustPolicyO8evaluateSbSo03SecC0C_SS7forHosttFTf4ggXn_n)(
                      v67,
                      v38,
                      v40,
                      v42,
                      v47,
                      v49,
                      v51);
              swift_unknownRelease(v67);
              swift_unknownRelease(v42);
              if ( v68 & 1 )
              {
                v69 = (void *)objc_allocWithZone(&OBJC_CLASS___NSURLCredential);
                v13 = objc_msgSend(v69, "initWithTrust:", v67);
                swift_unknownRelease(v67);
                if ( (unsigned __int8)v51 == 4 )
                {
                  swift_rt_swift_release(v49);
                }
                else if ( (unsigned __int8)v51 == 3 || (unsigned __int8)v51 == 2 )
                {
                  swift_bridgeObjectRelease(v47);
                }
                swift_unknownRelease(v42);
                v11 = 0LL;
              else
              {
                swift_unknownRelease(v67);
                if ( (unsigned __int8)v51 == 4 )
                {
                  swift_rt_swift_release(v49);
                }
                else if ( (unsigned __int8)v51 == 3 || (unsigned __int8)v51 == 2 )
                {
                  swift_bridgeObjectRelease(v47);
                }
                swift_unknownRelease(v42);
                v13 = 0LL;
                v11 = 2LL;
              }
              goto LABEL_45;
```

可以看到这里主要是通过另一个验证函数来做验证，然后对验证结果做if判断。如果用验证结果为1，那么就v11=0，否则呢，就v13=0,v11=2。而且这里他调用验证函数的方式比较特殊，具体原理没研究，但是IDA会无法识别到函数，frida也无法找到这个函数的地址，所以直接hook验证函数就暂时不考虑了。

最后函数结束点是在LABEL_45，参数为v5,v11,v13。而验证通过影响的参数是v11，v13是返回值，也就是其他参数和验证是无关的，我们重点关注v11的取值过程。

```
LABEL_45:
    (*(void (__fastcall **)(__int64, __int64, void *))(v5 + 16))(v5, v11, v13);
    return objc_release(v13);
```

继续往后面看一点，发现如果serverTrust为0，也就是上面if(v67)这一行就没有进入if块，跟一下后面会发现v11=1。也就是说v11存在三个值，0：通过；2：不通过；1：不知道。那么我们修改serverTrust的返回值为0来验证一下这个不知道具体是什么情况。

测试的结果呢，是直接就可以绕过验证继续抓包了，由于我主要是需要绕过这个机制去分析流量，就没有进一步研究v5+16这个函数对v11的三个不同判断逻辑了。有兴趣的话可以交流一下。

####绕过方法
使用frida去hook函数`-[NSURLProtectionSpace serverTrust]`，修改返回值为0，即可完成绕过。但是这个修改并不是使得验证通过，而是是验证进入另一条路径，所以可能存在不稳定的情况，比如说部分内容仍然无法正常显示等。

核心代码如下：

JS部分：

```js
function hookObjC(funcname, argNum) {
    var name = funcname;
    resolver.enumerateMatches(name, {
        onMatch: function (match) {
                    send(match.name);
                    Interceptor.attach(match.address,{
                        onEnter: function (args) {
                                argArray[0] = match.name;
                                getObjCArgs(args, argNum);
                        },
        
                        onLeave: function(retval) { 
                            getRetVal(retval);
                            send(argArray);
                            retval.replace(0);
                        }
                    })
        },
        onComplete: function () {}
    });
}
```

python部分：

~~~Python
def rewritesrc():
    ss = ""
    argNum = '-[NSURLProtectionSpace serverTrust]'.count(":")
    ss = src + "setTimeout(function()\{\{hookObjC(\"-[NSURLProtectionSpace serverTrust]\", {0})\}\}, 0);".format(argNum)
    return ss

def main():
    app = u"洋钱罐"

    s = frida.get_usb_device().attach(app)
    script = s.create_script(rewritesrc())
    script.on('message', on_msg)
    script.load()

    sys.stdin.read()

def on_msg(msg, data):
    print msg

if __name__ == '__main__':
        main()
~~~

> `python fast_hook_ret_replace_objc.py '-[NSURLProtectionSpace serverTrust]'`

## 0x3 AFSecurityPolicy evaluateServerTrust:forDomain:
测试对象：微众银行（版本：2.4.3（606））

#### 分析过程
这个验证方法是AF库里面实现的，在微众银行下面把他稍作修改纳入到自己的SDK中了，具体代码直接搜索函数`-[PodWebankSDK_AFSecurityPolicy evaluateServerTrust:forDomain:]`就可以看到。

分析这个函数逻辑，发现一个有趣的东西。为了提供对更多场景的支持，代码中加入了一个`allowInvalidCertificates`的项，使用的逻辑如下述代码所示（代码来自IDA F5）

```c
  if ( (unsigned __int64)-[PodWebankSDK_AFSecurityPolicy allowInvalidCertificates](v5, "allowInvalidCertificates") & 1 )
  {
    v42 = 1;
  }
  else
  {
    if ( (unsigned int)SecTrustEvaluate(v4, &v111) )
    {
LABEL_42:
      v42 = 0;
      goto LABEL_75;
    }
    v42 = (_DWORD)v111 == 4 || (_DWORD)v111 == 1;
  }
```

这里如果允许无效证书，就直接将v42置1了，最后返回值也是v42，那么通过这里就可以很快判定这个函数返回值为1时，证书验证通过。

#### 绕过方法
直接用frida修改返回值为1，代码和上面一模一样就不再贴了。只需要把`retval.replace(0)`改成`retval.replace(1)`，然后把函数名换掉就行了。

>`python fast_hook_ret_replace_objc.py '-[PodWebankSDK_AFSecurityPolicy evaluateServerTrust:forDomain:]'`

## 0x4 非0/1实现
测试对象：云闪付（版本：v5.0.5）

通过一些花里胡哨的办法（hook serverTrust打印调用栈），我们找到了他的证书验证函数。
`-[MKNetworkOperation connection:willSendRequestForAuthenticationChallenge:]`

#### 分析过程

由于他是规范的自实现验证，所以还是调用了系统库的接口。很容易就能在验证函数中找到官方范例的代码影子。

看一下他对serverTrust的处理。

```
v78 = ((__SecTrust *(__cdecl *)(MKNetworkOperation *, SEL))objc_msgSend)(v4, "serverTrust");
if ( SecTrustGetCertificateCount(v78) < 1 )
{
  v81 = 0LL;
}
else
{
  ((void (__cdecl *)(MKNetworkOperation *, SEL))objc_msgSend)(v4, "serverTrust");
  v79 = SecTrustGetCertificateAtIndex();
  v80 = objc_msgSend(&OBJC_CLASS___NSString, "stringWithFormat:", CFSTR("%@"), v79);
  v81 = (void *)objc_retainAutoreleasedReturnValue(v80);
}
LODWORD(v153) = 0;
objc_msgSend(v81, "rangeOfString:", CFSTR("GeoTrust"));
if ( !v91 )
{
```

这里从获得serverTrustRef之后，直接取了第一项证书，然后用stringWithFormat硬做成了一个NSString，然后后面一大排比较，应该是白名单CA。只要这里的比较能够通过，后面的代码再没有任何验证机制，就进入响应阶段了。

由于不太懂对非字符串类型做stringWithFormat是个什么后果，我用cycript模拟了一下这个过程。结果是这样的（指针来自frida hook信息）。

```
cy# a = #0x102855890
#"<cert(0x102855890) s: tysdk.95516.com i: PortSwigger CA>"

cy# [NSString stringWithFormat:"%@",a]
@"<cert(0x102855890) s: tysdk.95516.com i: PortSwigger CA>"
```
也就是说，这种转换其实没有任何中间处理，直接把对象的描述信息打了出来。那么后面的比较其实就是直接在这个字符串里面搜索有没有白名单CA的名字了。

但是他这里的做法其实给我们带来了一项障碍。如果我们直接hook了SecTrustGetCertificateAtIndex的返回值，那么很可能无法正常取出证书；而如果我们去hook`-[NSString stringWithFormat:]`或`-[NSString rangeOfString:]`，由于是常用类，很可能会拖慢APP的速度。后面我采用的是第二种方案，尽管我尽力减少了代码量，APP运行速度还是有明显的迟钝感，这个地方仍待优化。

除此之外，这里还有另一个坑，如果直接用retval.replace(0x2)去替换返回值，会发现仍然无法通过检查。

具体原因在后面的比较代码中。

```
objc_msgSend(v81, "rangeOfString:", CFSTR("GeoTrust"));
if ( !v91 )
{
  objc_msgSend(v81, "rangeOfString:", CFSTR("VeriSign"));
  if ( !v92 )
  {
    objc_msgSend(v81, "rangeOfString:", CFSTR("Symantec"));
    if ( !v93 )
    {
      objc_msgSend(v81, "rangeOfString:", CFSTR("GlobalSign"));
      if ( !v94 )
      {
        objc_msgSend(v81, "rangeOfString:", CFSTR("Entrust"));
        if ( !v95 )
        {
          objc_msgSend(v81, "rangeOfString:", CFSTR("Thawte"));
          if ( !v96 )
          {
            objc_msgSend(v81, "rangeOfString:", CFSTR("DigiCert"));
            if ( !v97 )
              goto LABEL_77;
          }
        }
      }
    }
  }
}
```

这里可以看到，v91-v97的赋值完全不知道在哪里，只是凭感觉应该是和上面的rangeOfString:相关。跳到汇编具体看看（仅截取一段，其他的部分除了比较的目标字符串不一样，其他都相同）。

```
__text:00000001003B0A60                 ADRP            X8, #selRef_rangeOfString_@PAGE
__text:00000001003B0A64                 LDR             X21, [X8,#selRef_rangeOfString_@PAGEOFF]
__text:00000001003B0A68                 ADRP            X2, #cfstr_Geotrust@PAGE ; "GeoTrust"
__text:00000001003B0A6C                 ADD             X2, X2, #cfstr_Geotrust@PAGEOFF ; "GeoTrust"
__text:00000001003B0A70                 MOV             X0, X23 ; void *
__text:00000001003B0A74                 MOV             X1, X21 ; char *
__text:00000001003B0A78                 BL              _objc_msgSend
__text:00000001003B0A7C                 CBNZ            X1, loc_1003B0B10
```

前面是正常的传参没有问题，最后却不用返回值X0做跳转条件，而是用X1。暂时不太清楚这段代码的生成原理，但是默认返回值是X0，retval.replace自然也是替换X0，这就解释了为什么直接替换是无效的。

既然弄清楚了原因，再做处理就不难了。具体绕过见下一小节。

>PS：这个APP如果不用调试工具在程序入口下断点的话，非常考手速，必须APP一打开马上开始frida注入。

#### 绕过方法

> PS：APP内部有循环检测，如果你能找到检测的触发点，hook掉触发点就可以解决性能问题。不过就这么弄我在iPhone 6（10.2.1）上操作延迟也不大，看个人需求吧。

这里有两个方案，一是构造一个完整的cert对象，修改SecTrustGetCertificateAtIndex的返回值，这样对系统的速度影响几乎可以忽略不计，但是构造这个东西是一个很麻烦的过程，图省事的菜鸡就选择了直接hook相关的NSString方法，我hook的是`-[NSString rangeOfString:]`，对第0个参数做检查，如果包含Charles（我的抓包工具CA，因为这个APP的服务器对证书长度有要求，Burp的默认证书是1024bit，服务器要求是2048bit，不匹配仍然会导致部分抓包失败），就在onLeave中修改X1和X0（为了保险）的值。

核心代码：

JS部分：

```
function hookObjC(funcname, argNum) {
    var name = funcname;
    resolver.enumerateMatches(name, {
        onMatch: function (match) {
                    send(match.name);
                    var flag = 0;
                    var edit_cnt = 1;
                    var NSString = ObjC.classes.NSString;
                    ps = NSString.stringWithString_("Charles"); // If you use Burp, replace Charles with PortSwigger. And you may need to generate a 2048bits cert.

                    Interceptor.attach(match.address,{
                        onEnter: function (args) {
                                //if(edit_cnt < 3){
                                    tmp = ObjC.Object(args[0]);
                                    if(tmp.containsString_(ps)){
                                        console.log("HTTP Pinning detected. ", edit_cnt, " times.");
                                        if(flag == 0)
                                            flag = 1;
                                    }
                                //}
                        },

                        onLeave: function(retval) { 
                            if(flag == 1){
                               console.log("Bypassed.");
                               this.context['x1'] = 0x25;
                               retval.replace(0x25);
                               flag = 0;
                               edit_cnt = edit_cnt + 1;
                            }
                        }
                    })
        },
        onComplete: function () {}
    });
}
```

Python部分：

```
def rewritesrc(funcname):
    ss = ""
    argNum = funcname.count(":")
    ss = src + "setTimeout(function(){{hookObjC(\"{0}\", {1})}}, 0);".format(funcname, argNum)

    return ss

def main():
    app = u"云闪付"

    s = frida.get_usb_device().attach(app)
    script = s.create_script(rewritesrc("-[NSString rangeOfString:]"))
    script.on('message', on_msg)
    script.load()

    sys.stdin.read()

def on_msg(msg, data):
    print msg
```