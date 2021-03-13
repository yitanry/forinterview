# **基于IPFS pubsub的通讯工具**

划水项目，以[IPFS]()的pubsub功能作为通讯底层基础，在其上构建命令行应用。  
计划使用python和golang分别实现。

## 可行性

v1：可行性应该不高（？），目前对于NAT及P2P协议了解不深，无法代码实现点对点通讯。命令行应用启动后（底层IPFS）加入公网，希望两个应用能够互相连接。

## **架构**

v1：
```
      cli cmd
         |
    -----------
    cli server
         |
    -----------
      ipfs api
         |   
       ------  
IPFS(public cluster)
```

cli启动服务后会创建两个服务，分别是cli server（负责执行cli cmd和监听ipfs事件）、ipfs daemon。