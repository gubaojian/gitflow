## hwws和admin消息格式梳理：
通信协议尽量用文本可扩展的消息格式，增加强可读性和可维护性。内部消息可以用自定义二进制，外部消息一律文本和字符串。
文档上用统一json定义内部通信协议，因为二进制书写不方便，实际通信是自定义二进制，包含json含义信息即可，json只是用来写文档和表达意思。
通用消息参数参数：
{
  "authId" : "",
  "appId" : "",
  "connId": "",
  "clientIp": "",
  "hwssId" : "",
  "action": "auth",
  "source": "wss",
  "msg" : "客户端的json或者文本消息"
}

hwssId 来标识 hwss 服务器的Id，多台服务器不同。方便admin和router定位机器。



1、客户端发起认证消息

client获取认证id和token后，向hwss发起授权请求，格式为json，消息体如下：限制消息体大小为4-8k。

{
  "authId": "required field authId",
  "authToken": "required field authToken",
  "xx": "custom extends",
  "yy": "auth"
}

若客户端发送无效消息，hwss响应出错消息，消息为：

{
  "msg": "please send authId & authToken",
  "success": "false",
  "action": "hwss-system"
}


hwss收到请求后，带上协议字段，封装消息请求admin消息：

{
  "authId" : "",
  "connId": "",
  "clientIp": "",
   "appId" : "",
   "hwssId" : "",
  "action": "auth",
  "source": "wss",
  "msg" : "客户端的json或者文本消息"
}


admin把业务处理的business_msg封装返回给hwss消息格式如下：

{
  "authId" : "",
  "connId": "",
  "hwssId" : "",
  "action": "auth",
  "msg" : "business_msg"
}

其中 msg必须包含json格式 : 
{
  "success" : "true"
}

hwss收到授权通过消息，根据success标识，进行授权标识，并将消息发送客户端。未认证客户端仅可发送8条消息。


2、客户端授权成功后向管理端发文本消息
客户端发送文本消息内容为 msg_text. hwss找到对应管理端的分组，将消息发送给管理端。

2.1 hwss 向 admin转发消息消息格式为：

{
  "authId" : "",
  "connId": "",
  "appId" : "",
  "clientIp": "",
  "hwssId" : "",
  "action": "msg",
  "source": "wss",
  "msg" : "客户端的json或者文本消息"
}


2.2、认证消息响应
admin收到消息后，进行业务处理，业务处理消息为：business_msg。 admin响应消息格式如下：
{
  "authId" : "",
  "connId": "",
  "hwssId" : "",
  "action": "msg",
  "msg" : "business_msg"
}


3、客户端授权成功后向管理端发二进制消息
客户端发送文本消息内容为 msg_binary. hwss找到对应管理端的分组，将消息发送给管理端。

3.1 hwss 向 admin转发消息消息格式为：

{
  "authId" : "",
  "connId": "",
  "clientIp": "",
  "appId" : "",
  "hwssId" : "",
  "action": "msg_binary",
  "source": "wss",
  "msg" : "msg_binary"
}


3.2、认证消息响应
admin收到消息后，进行业务处理，业务处理消息为：business_msg。 admin响应消息格式如下：
{
  "authId" : "",
  "connId": "",
  "hwssId" : "",
  "action": "msg/msg_binary",
  "msg" : "business_msg"
}

根据hwssId决定是否需要route消息。

4、管理端向连接的hwss单点client单独发消息：
管理端将business_msg 封装成协议消息，action根据格式封装为msg或者二进制 msg_binary，简称msgb . authId和connId必须都带。
{
  "authId" : "",
  "connId": "",
  "hwssId" : "",
  "action": "msg/msg_binary",
  "msg" : "business_msg"
}

hwss 收到请求后,hwssId不是本机的话，交给router处理，是本机解析消息，找到本机对应的连接，然后把 business_msg转发给客户端，
若本机找不到connId响应报错（暂时不做）， 报错消息为：
{
  "msg": "connId not found connId",
  "action": "hwss-system"
}


5、管理端向连接的hwss多个client发消息：
管理端将business_msg 封装成协议消息，action根据格式封装为msg或者二进制 msg_binary，简称msgb。authId和connId必须都带。

{
  "action": "groupMsg",
  "route": "false/true 是否需要路由处理，默认需要，标记本机还是集群发消息",
  "groupMsgList": [
    {
      "clients": [
        {
          "authId": "",
          "connId": "",
           "hwssId" : "",
        }
      ],
      "msgList": [
        {
          "action": "msg/msg_binary",
          "msg": "business_msg"
        }
      ]
    }
  ]
}

msgb 暂时不支持。

hwss 对于群发消息，不需要route的消息，本地处理。需要route的消息，直接转发给router处理。


6、管理端向管理订阅：

6.1 将对应的client加入话题，消息格式如下
{
  "authId" : "",
  "connId": "",
  "hwssId" : "",
  "route"  :  "true/false",
  "action": "subtopic",
  "msg" : "business_msg"
}

6.2 将对应的client取消订阅话题：
{
  "authId" : "",
  "connId": "",
  "hwssId" : "",
  "route"  :  "true/false",
  "action": "subtopic",
  "msg" : "business_msg"
}


6.3 向主题发送消息：
{
  "route": "true/false",
  "action": "topic_msg",
  "msgList": [
    {
      "topic" : "",
      "action": "msg/msg_binary",
      "msg": "business_msg"
    }
  ]
}
默认需要群发，可以控制不群发。

6.4 关闭topic
{
  "authId" : "",
  "connId": "",
  "hwssId" : "",
  "route"  :  "true/false",
  "action": "closetopic",
  "msg" : {
      "topic" : "xx"
    }
}


7、主动关闭客户端连接消息：
{
  "authId" : "",
  "connId": "",
  "hwssId" : "",
  "route" : "true/false", ??
  "action": "close",
  "msg" : "close message"
}

hwss管理, 关闭客户端，并把关闭消息发送给客户端。


8、hwss内部响应消息：
hwss响应消息统一为，action都为hwss-system：
{
  "msg": "please send authId & authToken",
  "success": "false",
  "action": "hwss-system"
}

{
  "msg": "please send msg after auth",
  "success": "false",
  "action": "hwss-system"
}


