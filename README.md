#snail的服务端

---

##overview

使用`Pyhon`、`Flask`框架，实现`RESTful api`服务器端。

HTTP方法    |URI                                                  |动作           
 ---------- |-----------------------------------------------------|------------- 
GET         |http://api.chih.me/snail/api/v0.1/users              |检索所有用户
GET         |http://api.chih.me/snail/api/v0.1/users/[id]         |检索单个用户
POST        |http://api.chih.me/snail/api/v0.1/users              |创建新用户 
PUT         |http://api.chih.me/snail/api/v0.1/users/[id]         |更新用户信息
DELETE      |http://api.chih.me/snail/api/v0.1/users/[id]         |删除用户
GET         |http://api.chih.me/snail/api/v0.1/ok                 |登录验证
GET         |http://api.chih.me/snail/api/v0.1/token              |获取token
GET         |http://api.chih.me/snail/api/v0.1/pic/[sha1]         |获取图片
GET         |http://api.chih.me/snail/api/v0.1/queses             |检索所有问题
GET         |http://api.chih.me/snail/api/v0.1/queses/[id]        |检索单个问题
POST        |http://api.chih.me/snail/api/v0.1/queses             |上传问题
POST        |http://api.chih.me/snail/snail/api/v0.1/quesesofcomp |检索公司下的问题
GET         |http://api.chih.me/snail/api/v0.1/comps              |检索所有公司 
GET         |http://api.chih.me/snail/api/v0.1/comps/[id]         |检索单个公司 
POST        |http://api.chih.me/snail/api/v0.1/comps              |上传公司
POST        |http://api.chih.me/snail/api/v0.1/upload             |上传图片
GET         |http://api.chih.me/snail/api/v0.1/pic/[sha1]         |查看图片
GET         |http://api.chih.me/snail/api/v0.1/answers            |检索所有答案
GET         |http://api.chih.me/snail/api/v0.1/answers/[id]       |检索单个答案
POST        |http://api.chih.me/snail/api/v0.1/answers            |上传答案
POST        |http://api.chih.me/snail/snail/api/v0.1/answersofques_new|检索问题下的答案(时间)
POST        |http://api.chih.me/snail/snail/api/v0.1/answersofques_hot|检索问题下的答案（点赞）
GET         |http://api.chih.me/snail/api/v0.1/practices          |检索所有实习
GET         |http://api.chih.me/snail/api/v0.1/practice/[id]      |检索单个实习
POST        |http://api.chih.me/snail/api/v0.1/practices          |上传实习
POST        |http://api.chih.me/snail/snail/api/v0.1/practicesofcomp|检索公司下的实习

##API调用说明

服务端已经部署，地址为 
    
    api.chih.me


用户与认证    
---

###用户注册

    $ curl -u miguel:python -i -X POST -H "Content-Type: application/json" -d '{"username":"test","nickname":"查尔斯","password":"python","sha1":"xxxxxxxxxxxxx","type":"student"}' http://api.chih.me/snail/api/v0.1/users
    
通过`POST` 传送`json` （数据类型待完善）(通过已有密码或token保护)

成功返回json格式用户名，错误返回处理后json格式的400 `{'error': 'Bad Request'}`

###获取所有用户信息

    $ curl -u miguel:python -i -X GET http://api.chih.me/snail/api/v0.1/users

###获取单个用户信息

    $ curl -u miguel:python -i -X GET http://api.chih.me/snail/api/v0.1/users/username

###密码认证

    $ curl -u miguel:python -i -X GET http://api.chih.me/snail/api/v0.1/ok
    
指定用户、密码，验证通过则返回`{'isok': 'ok!'}`

###token认证

    $ curl -u miguel:python -i -X GET http://api.chih.me/snail/api/v0.1/token
    
指定用户密码GET `http://api.chih.me//snail/api/v0.1/token` 返回token

    $ curl -u TOKEN -i -X GET http://api.chih.me/snail/api/v0.1/users

指定用户为token，密码为空获取资源，token有有效期，为十分钟

问题
---

###问题上传

    $ curl -u miguel:python -i -X POST -H "Content-Type: application/json" -d '{"comp_id":"1","user_id":"1","sha1":"xxxxxxxxxxxxx","title":"test","content":"gggggggggggggggggggggg"}' http://api.chih.me/snail/api/v0.1/queses
注意：问题类型为`已存在`的公司类型

###获取所有问题信息

    $ curl -u miguel:python -i -X GET http://api.chih.me/snail/api/v0.1/queses


###获取单个问题信息

    $ curl -u miguel:python -i -X GET http://api.chih.me/snail/api/v0.1/queses/1
    
    
###检索公司下的问题

    $ curl -u miguel:python -i -X POST -H "Content-Type: application/json" -d '{"comp_id":"1"}' http://api.chih.me/snail/api/v0.1/quesesofcomp

答案
---

###检索所有答案

    $ curl -u miguel:python -i -X GET http://api.chih.me/snail/api/v0.1/answers


###检索单个答案

    $ curl -u miguel:python -i -X GET http://api.chih.me/snail/api/v0.1/answer/1


###上传答案

    $ curl -u miguel:python -i -X POST -H "Content-Type: application/json" -d '{"ques_id":"5","user_id":"4","number":"3","sha1":"xxxxxxxxxxxxx","content":"gggggggggggggggggggggg"}' http://api.chih.me/snail/api/v0.1/answers

ques_id,user_id必须已经存在

###检索问题下的答案

    $ curl -u miguel:python -i -X POST -H "Content-Type: application/json" -d '{"ques_id":"1"}' http://api.chih.me/snail/api/v0.1/answersofques_[hot|new]

公司
---

###公司信息上传

    $ curl -u miguel:python -i -X POST -H "Content-Type: application/json" -d '{"type":"计算机","name":"阿里巴巴"}' http://api.chih.me/snail/api/v0.1/comps


###获取所有公司信息

    $ curl -u miguel:python -i -X GET http://api.chih.me/snail/api/v0.1/comps


###获取单个公司信息

    $ curl -u miguel:python -i -X GET http://api.chih.me/snail/api/v0.1/comps/1

实习
---

###检索所有实习

    $ curl -u miguel:python -i -X GET http://api.chih.me/snail/api/v0.1/practices


###检索单个实习

    $ curl -u miguel:python -i -X GET http://api.chih.me/snail/api/v0.1/practice/1


###上传实习

    $ curl -u miguel:python -i -X POST -H "Content-Type: application/json" -d '{"title":"title","office":"职位","type":"type","comp_id":"comp_id","comp_size":"comp_size","addr":"addr","money":"money","ask":"要求","duty":"职责"}' http://api.chih.me/snail/api/v0.1/practices

comp_id必须已经存在

###检索公司下的实习

    $ curl -u miguel:python -i -X POST -H "Content-Type: application/json" -d '{"comp_id":"1"}' http://api.chih.me/snail/api/v0.1/practicesofcomp

图片
---

###上传图片

表单 
    
        <form action='/snail/api/v0.1/upload' method='post' enctype='multipart/form-data'>
            <input type='file' name='uploaded_file'>

返回图片sha1 
  
    {
        "sha1": "72e61b143f989fcfb12b01be71eeda18c210a135"
    }


###获取图片


    $ curl -u miguel:python -i -X GET http://api.chih.me/snail/api/v0.1/pic/sha1  
    
 