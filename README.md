#snail的服务端

---

##overview

使用`Pyhon`、`Flask`框架，实现`RESTful api`服务器端。

HTTP方法    |URI                                          |动作           
 ---------- |---------------------------------------------|------------- 
GET         |http://api.chih.me//snail/api/v0.1/users     |检索所有用户
GET         |http://api.chih.me//snail/api/v0.1/users/[id]|检索单个用户
POST        |http://api.chih.me//snail/api/v0.1/users     |创建新用户 
PUT         |http://api.chih.me//snail/api/v0.1/users/[id]|更新用户信息
DELETE      |http://api.chih.me//snail/api/v0.1/users/[id]|删除用户  


##API调用说明

服务端已经部署，地址为 
    
    api.chih.me
    

###用户注册

    $ curl -u miguel:python -i -X POST -H "Content-Type: application/json" -d '{"username":"test","password":"python"}' http://api.chih.me//snail/api/v0.1/users
    
通过`POST` 传送`json` （数据类型待完善）(通过已有密码或token保护)

成功返回json格式用户名，错误返回处理后json格式的400

###密码认证

    $ curl -u miguel:python -i -X GET http://api.chih.me//snail/api/v0.1/users
    
指定用户、密码

###token认证

    $ curl -u miguel:python -i -X GET http://api.chih.me//snail/api/v0.1/token
    
指定用户密码GET `http://api.chih.me//snail/api/v0.1/token` 返回token

    $ curl -u TOKEN -i -X GET http://api.chih.me//snail/api/v0.1/users

指定用户为token，密码为空获取资源，token有有效期，为十分钟

