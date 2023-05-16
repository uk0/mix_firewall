package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"time"
)

const (
	pcapDev     = "en0"
	packetLimit = 10000       // 触发防火墙规则的数据包数量
	cooldown    = time.Minute // 防火墙规则的冷却时间
)

func main() {
	// 读取 pcap 文件
	handle, err := pcap.OpenLive(pcapDev, 1600, true, pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// 创建一个 IP 地址到时间戳的映射
	ipTimestamps := make(map[string][]time.Time)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// 获取源 IP 地址
		if ipLayer := packet.NetworkLayer(); ipLayer != nil {
			srcIP := ipLayer.NetworkFlow().Src().String()

			// 记录时间戳
			ipTimestamps[srcIP] = append(ipTimestamps[srcIP], time.Now())

			// 检查是否有过多的数据包
			if len(ipTimestamps[srcIP]) > packetLimit {
				// 添加到防火墙
				fmt.Printf("Adding %s to firewall...\n", srcIP)
				// 在这里调用你的防火墙 API

				// 清理记录
				ipTimestamps[srcIP] = nil

				// 设置冷却时间
				time.AfterFunc(cooldown, func() {
					fmt.Printf("Removing %s from firewall...\n", srcIP)
					// 在这里调用你的防火墙 API
				})
			}
		}
	}
}
