package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"time"
)

const (
	pcapDev     = "en0"
	packetLimit = 10              // 触发防火墙规则的数据包数量
	cooldown    = time.Second * 5 // 防火墙规则的冷却时间
)

func isPrivate(cip string) bool {
	ip := net.ParseIP(cip)
	privateIPBlocks := []string{
		"10.0.0.0/8",     // Private IPv4 range
		"172.16.0.0/12",  // Private IPv4 range
		"192.168.0.0/16", // Private IPv4 range
		"fc00::/7",       // Private IPv6 range
		"fe80::/10",      // Link-local Unicast in IPv6
	}

	for _, block := range privateIPBlocks {
		_, subnet, _ := net.ParseCIDR(block)
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func addFirewallRule(ip string) error {
	switch runtime.GOOS {
	case "windows":
		return runCommand("netsh", "advfirewall", "firewall", "add", "rule", "name=BlockIP", "dir=in", "action=block", "remoteip="+ip, "enable=yes")
	case "linux":
		// 检查是使用 iptables 还是 firewalld
		if isCommandAvailable("firewalld") {
			return runCommand("sudo", "firewall-cmd", "--permanent", "--add-rich-rule='rule family=\"ipv4\" source address=\""+ip+"\" drop'")
		} else {
			return runCommand("sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
		}
	case "darwin":
		// 在 MacOS 上，你可能需要首先创建一个 pf 文件，然后将阻止规则添加到这个文件中
		// 这需要管理员权限
		return runCommand("pfctl", "-t", "black_ip_lists", "-T", "add", ip)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func deleteFirewallRule(ip string) error {
	switch runtime.GOOS {
	case "windows":
		return runCommand("netsh", "advfirewall", "firewall", "delete", "rule", "name=BlockIP", "remoteip="+ip)
	case "linux":
		if isCommandAvailable("firewalld") {
			return runCommand("sudo", "firewall-cmd", "--permanent", "--remove-rich-rule='rule family=\"ipv4\" source address=\""+ip+"\" drop'")
		} else {
			return runCommand("sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
		}
	case "darwin":
		// 删除 MacOS 上的阻止规则
		return runCommand("pfctl", "-t", "black_ip_lists", "-T", "delete", ip)
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func isCommandAvailable(name string) bool {
	cmd := exec.Command("/bin/sh", "-c", "command -v "+name)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}
func runCommand(name string, arg ...string) error {
	cmd := exec.Command(name, arg...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func Watch() {
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
				if isPrivate(srcIP) {
					fmt.Printf("%s is a private IP address, skipping...\n", srcIP)
					return
				}
				err := addFirewallRule(srcIP)
				if err != nil {
					log.Fatal(err)
				}

				// 清理记录
				ipTimestamps[srcIP] = nil

				// 设置冷却时间
				time.AfterFunc(cooldown, func() {
					fmt.Printf("Removing %s from firewall...\n", srcIP)
					err := deleteFirewallRule(srcIP)
					if err != nil {
						log.Fatal(err)
						return
					}
				})
			}
		}
	}
}

func main() {
	uid := os.Geteuid()
	fmt.Println("UID:", uid)
	if uid == 0 {
		fmt.Println("Running as root.")
		Watch()
	} else {
		fmt.Println("Not running ")
		return
	}
}
