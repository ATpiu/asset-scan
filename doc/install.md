# 安装文档

## 机器配置

由于Es运行比较吃内存，建议Es和Kibana放在一台机器上（内存4G及以上）

若Es、Kibana和asset-scan放置在一台机器，建议内存8G及以上（最少6G）

## nmap和masscan安装

**nmap建议安装最新的7.8版本，准确性较之前有明显的提升**

### nmap安装

```wget https://nmap.org/dist/nmap-7.80-1.x86_64.rpm && rpm -ivh nmap-7.80-1.x86_64.rpm```

### masscan安装

```yum install -y masscan```

## 安装 Elasticsearch 5.6.8版本(暂不支持6.x及以上版本)

- Centos安装java环境

```yum -y install java-1.8.0-openjdk*```

- 下载Es并解压

```
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-5.6.8.tar.gz && tar -zxvf elasticsearch-5.6.8.tar.gz -C /opt
```

- 新建一个非 root 权限用户，-p 后跟设定的密码，ES就使用这个用户起。

```
groupadd elasticsearch && useradd elasticsearch -g elasticsearch -p Es12345678
```

- 修改文件夹所属用户和组为 elasticsearch:elasticsearch

```
chown -R elasticsearch:elasticsearch /opt/elasticsearch-5.6.8
```

- Centos7以下系统在config/elasticsearch.yml中添加 

```
bootstrap.system_call_filter: false
```

- 启动Es

```
su - elasticsearch -c '/opt/elasticsearch-5.6.8/bin/elasticsearch -d'
```

- curl下确认Es启动成功

```
curl -XGET -s "http://localhost:9200/_cluster/health?pretty"
```

## 安装 Kibana 5.6.8版本

- 下载Kibana并解压

```
wget https://artifacts.elastic.co/downloads/kibana/kibana-5.6.8-linux-x86_64.tar.gz && tar -zxvf kibana-5.6.8-linux-x86_64.tar.gz -C /opt
```
- 在/opt/kibana-5.6.8-linux-x86_64/config/kibana.yml中增加以下配置并保存

```
server.host: "0.0.0.0"
```

- 输入`nohup /opt/kibana-5.6.8-linux-x86_64/bin/kibana > /dev/null 2>&1 &`,开启kibana 

- 浏览器中输入：`http://xx.xx.xx.xx:5601`（kibana所在ip地址），访问成功后，点击左侧菜单栏`Management`,配置索引。
在`Index pattern`中输入`scan-*`，`Time Filter field name`下拉框选择`time`字段，即完成kibana的配置
