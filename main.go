package main

import (
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"log"
	"regexp"
	"time"
)

var (
	device      string = "\\Device\\NPF_{9FB18C43-0331-4994-B6CB-BDD0C457F793}"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)

var dbGlobal *gorm.DB

func main() {
	initDb()
	// 打开某一网络设备
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		printPacketInfo(packet)
	}
	defer dbGlobal.Close()
}
func printPacketInfo(packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		if ethernetPacket.EthernetType.String() == "IPv4" {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)
				dstIP := ip.DstIP.String()
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					applicationLayer := packet.ApplicationLayer()
					if applicationLayer != nil {
						payload := string(applicationLayer.Payload())
						if "123.57.13.246" == dstIP && "8080(http-alt)" == tcp.DstPort.String() {
							fmt.Println(payload)
							method := getMethod(payload)
							host := getValue(payload, "Host:\\s(.*?)\n")
							userAgent := getValue(payload, "User-Agent:\\s(.*?)\n")
							origin := getValue(payload, "Origin:\\s(.*?)\n")
							referer := getValue(payload, "Referer:\\s(.*?)\n")
							cookie := getValue(payload, "Cookie:\\s(.*?)\n")
							if host != "" {
								httpBaseObj := &HttpBase{
									Method:    method,
									Host:      host,
									UserAgent: userAgent,
									Origin:    origin,
									Referer:   referer,
									Cookie:    cookie,
								}
								dbGlobal.Create(httpBaseObj)
								marshal, _ := json.Marshal(httpBaseObj)
								fmt.Println(string(marshal))
							}
							fmt.Println("----------------------------------------------------------------------------------------------------------")
						}
					}
				}
			}
		}
	}
}

func getValue(payload string, reg string) string {
	hostReg := regexp.MustCompile(reg)
	host := hostReg.FindStringSubmatch(payload)
	if len(host) > 1 {
		return host[1]
	}
	return ""
}

func getMethod(payload string) string {
	hostReg := regexp.MustCompile("(.*?)\\s\\/")
	host := hostReg.FindStringSubmatch(payload)
	if len(host) > 1 {
		return host[1]
	}
	return ""
}

func initDb() {
	db, err := gorm.Open("mysql", "root:root-abcd-1234@tcp(123.57.13.246:3306)/http_info?charset=utf8&parseTime=True&loc=Local")
	if err != nil {
		panic("连接数据库失败")
	}
	// 自动迁移模式
	db.AutoMigrate(&HttpBase{})
	dbGlobal = db
}
