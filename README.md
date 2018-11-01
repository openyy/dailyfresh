# dailyfresh

## mysql 给远程客户端授权:  
    1. grant all privileges on 'username'@'host' with grant option;
    2. flush privileges;

## 如何在virtualenv环境中安装指定的python版本
    virtualenv 虚拟环境文件目录名 python=python3.6

## FastFDS启动失败解决方法
	执行 sudo service fdfs_trackerd start 
	报 Failed to start fdfs_trackerd.service: Unit fdfs_trackerd.service not found.服务找不到时
	执行 /usr/bin/fdfs_trackerd /etc/fdfs/tracker.conf start 即可，storage同理
    
## import找不到模块解决方法
    右击文件夹，点击Mark Directory as -> Sources Root 即可
    
## 在系统级修改 Python 版本
    我们可以使用 update-alternatives 来为整个系统更改 Python 版本。以 root 身份登录，首先罗列出所有可用的 python 替代版本信息：
    
    1	# update-alternatives --list python
    2	update-alternatives: error: no alternatives for python
    如果出现以上所示的错误信息，则表示 Python 的替代版本尚未被 update-alternatives 命令识别。想解决这个问题，我们需要更新一下替代列表，将 python2.7 和 python3.4 放入其中。
    
    1	# update-alternatives --install /usr/bin/python python /usr/bin/python2.7 1
    2	update-alternatives: using /usr/bin/python2.7 to provide /usr/bin/python (python) in auto mode
    3	# update-alternatives --install /usr/bin/python python /usr/bin/python3.4 2
    4	update-alternatives: using /usr/bin/python3.4 to provide /usr/bin/python (python) in auto mode
    --install 选项使用了多个参数用于创建符号链接。最后一个参数指定了此选项的优先级，如果我们没有手动来设置替代选项，那么具有最高优先级的选项就会被选中。这个例子中，我们为 /usr/bin/python3.4 设置的优先级为2，所以update-alternatives 命令会自动将它设置为默认 Python 版本。
    
    1	# python --version
    2	Python 3.4.2
    接下来，我们再次列出可用的 Python 替代版本。
    
    1	# update-alternatives --list python
    2	/usr/bin/python2.7
    3	/usr/bin/python3.4
    现在开始，我们就可以使用下方的命令随时在列出的 Python 替代版本中任意切换了。
    
    1	# update-alternatives --config python
    
    1	# python --version
    2	Python 2.7.8
    
## Django2.1 
    1.urlpattern中要使用xxview.as_view()
	2.使用外键的地方foreignkey要加上on_delete=models.CASCADE
	3.使用pymysql要在__init__.py中加上
		import pymysql
		pymysql.install_as_MySQLdb(）
   	4.远程授权登录mysql
        	在数据库服务器输入: grant all privileges on 数据库名.* to '用户名'@'客户端ip' with grant option;
	5.Django2.1用户认证系统authenticate()一直返回None:
		import django.contrib.auth.hashers import check_password,  make_password
		使用User.objects.cteate_user()创建用户，并在调用user.save()保存用户信息之前: user.password = make_password(password)
		在验证用户登录处：
			try:
			    user = User.objects.get(username=username)
            		    pwd = user.password
           		    if check_password(password, pwd):
			        if user.is_active:
			            login(request, user)
				    return xxxx
			    else:
			        return xxxx
        		except User.DoesNotExist:
            		    return xxxx
		
  
