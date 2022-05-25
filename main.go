package main

import (
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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

func main() {
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
					//tcp, _ := tcpLayer.(*layers.TCP)
					applicationLayer := packet.ApplicationLayer()
					if applicationLayer != nil {
						payload := string(applicationLayer.Payload())
						if "123.57.13.246" == dstIP {
							//fmt.Println(payload)
							method := getMethod(payload)
							host := getValue(payload, "Host:\\s(.*?)\n")
							userAgent := getValue(payload, "User-Agent:\\s(.*?)\n")
							origin := getValue(payload, "Origin:\\s(.*?)\n")
							referer := getValue(payload, "Referer:\\s(.*?)\n")
							cookie := getValue(payload, "Cookie:\\s(.*?)\n")
							httpBaseObj := &HttpBase{
								Method:    method,
								Host:      host,
								UserAgent: userAgent,
								Origin:    origin,
								Referer:   referer,
								Cookie:    cookie,
							}
							marshal, _ := json.Marshal(httpBaseObj)
							fmt.Println(string(marshal))
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
