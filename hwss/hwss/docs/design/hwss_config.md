
## 配置文件格式如下：

needAuth统一有admin控制，控制台不做配置。

{
  "hwssId" : "", 
  "maxConnNum": 800000,
  "client" : [
      {
        "appId" : "",
        "appToken" : "",
        "needAuth" : true 
      }
  ],
  "servers" : [
     {
        "clientAppIds" : [],
        "serverAppId" : "appId",
        "serverAppToken": "",
        "authId" : "authId",
        "authToken" : "",
        "privateKey": "44",
         "publicKey" : "",
         "checkAuthTime" : true,
         "enableRouter" : "true/false"
     },
     {
        "clientAppIds" : [],
        "serverAppId" : "appId",
        "serverAppToken": "",
        "authId" : "authId",
        "authToken" : "",
        "privateKey": "44",
         "publicKey" : "",
         "checkAuthTime" : true,
         "enableRouter" : "true/false"
     }
  ],
  "routers" : [
     {
        "routerAppId" : "appId",
        "routerToken" : "",
        "authId" : "authId",
        "authToken" : "",
        "privateKey": "44",
         "publicKey" : "",
         "checkAuthTime" : true
     }
  ]
}