## hwws和router消息格式梳理：

hwss对于来之router的消息，不再做任何转发处理。

1、router收到的单个消息，收到hwss转发消息格式如下：

{
  "authId" : "",
  "connId": "",
  "hwssId" : "",
  "action": "msg/msg_binary",
  "msg" : "business_msg"
}

找到对应的hwssId，然后原封不动转发处理。找不到记录日志（？？）
router可以做一定的消息缓存？


2、router收到的群发消息，收到hwss转发消息格式如下：
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

找到对应主机，然后原转发到hwss。  hwss收到消息过滤群发即可。


