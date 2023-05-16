### mix_firewall



#### 简易的pcap检测工具


#### TODO

* 支持Rego规则
* 支持多种协议 http tcp udp 的数据包内容检测


#### 使用方法

* build and run


#### 自己改一下代码才能用

```go
const (
	pcapDev     = "en0"           // 相关设备
	packetLimit = 10              // 触发防火墙规则的数据包数量
	cooldown    = time.Second * 5 // 防火墙规则的冷却时间
)
```