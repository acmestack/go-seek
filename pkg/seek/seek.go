package seek

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"regexp"
	"strings"
	"time"
)

var (
	device      string = "Intel(R) Ethernet Connection (2) I219-V"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)

var (
	businessSystemIdReg string = "junSid=([0-9a-zA-Z]+)"
	userIdReg           string = "junUid=([0-9a-zA-Z%]+)"
	machineIdReg        string = "junMid=([0-9a-zA-Z]+)"
	extendedInfoReg     string = "junExt=([0-9a-zA-Z{}]+)"
	urlReg              string = "\\s(\\/.*)\\sHTTP"
	hostReg             string = "Host:\\s(.*)"
	userAgentReg        string = "User-Agent:\\s(.*)"
)

func StartSeek() {

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Println("执行错误：", err.Error())
	}
	fmt.Println(devices)
	for _, v := range devices {
		if v.Description == device {
			go startSync(v.Name)
		}
	}

}

func startSync(deviceName string) {
	handle, err = pcap.OpenLive(deviceName, snapshotLen, promiscuous, timeout)
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
				//ip, _ := ipLayer.(*layers.IPv4)
				//dstIP := ip.DstIP.String()
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					//tcp, _ := tcpLayer.(*layers.TCP)
					applicationLayer := packet.ApplicationLayer()
					if applicationLayer != nil {
						payload := string(applicationLayer.Payload())
						if strings.Contains(payload, "http") {
							//if "192.168.3.33" == dstIP && "8080(http-alt)" == tcp.DstPort.String() {
							fmt.Println(payload)
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

func getOneStringByRegex(str, rule string) string {
	reg, err := regexp.Compile(rule)
	if reg == nil || err != nil {
		return ""
	}
	//提取关键信息
	result := reg.FindStringSubmatch(str)
	if len(result) < 1 {
		return ""
	}
	return result[1]
}
