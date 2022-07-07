package seek

import (
	"encoding/json"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"regexp"
	"strconv"
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

func StartSeek(name string) {
	openSync(name)
}

func openSync(deviceName string) {
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
				ip, _ := ipLayer.(*layers.IPv4)
				dstIP := ip.DstIP.String()
				srcIp := ip.SrcIP.String()
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					dstPort := tcp.DstPort.String()
					applicationLayer := packet.ApplicationLayer()
					if applicationLayer != nil {
						payload := string(applicationLayer.Payload())
						if strings.Contains(payload, "http") {
							sid := getOneStringByRegex(payload, businessSystemIdReg)
							uid := getOneStringByRegex(payload, userIdReg)
							mid := getOneStringByRegex(payload, machineIdReg)
							ext := getOneStringByRegex(payload, extendedInfoReg)
							url := ""
							ua := getOneStringByRegex(payload, userAgentReg)
							reqc := ""
							sa := dstIP + ":" + dstPort
							sd := getOneStringByRegex(payload, hostReg)
							ct := time.Now()
							reqt := time.Now()
							t := 0
							dstIp := dstIP
							srcIp := getSrcIp(payload, srcIp)
							srcSeq := strconv.Itoa(int(tcp.Seq))
							fmt.Println(payload)
							fmt.Println("----------------------------------------------------------------------------------------------------------")
							serviceLog := MongoServiceLog{
								T:      t,
								Sid:    sid,
								Sd:     sd,
								Sa:     sa,
								Uid:    uid,
								Duid:   "",
								Mid:    mid,
								Url:    url,
								Reqt:   reqt,
								Reqc:   reqc,
								SrcIp:  srcIp,
								DstIp:  dstIp,
								SrcSeq: srcSeq,
								Ua:     ua,
								Ext:    ext,
								Ct:     ct,
							}
							marshal, _ := json.Marshal(serviceLog)
							fmt.Println(string(marshal))
							fmt.Println("----------------------------------------------------------------------------------------------------------")
							//execute := httpclient.Post("http://192.168.3.37:9128/ajax/addServiceLogForJava").Json(serviceLog).Execute()
							//defaultClient := &http.Client{}
							//response, _ := defaultClient.Post("http://192.168.3.37:9128/ajax/addServiceLogForJava", "application/json", strings.NewReader(string(marshal)))
							//log.Println(response.Body)
							//log.Println(response.Body)

						}
					}
				}
			}
		}
	}
}

// todo 配置clientIP 正则
func getSrcIp(payload string, srcIp string) string {
	clientIp := getOneStringByRegex(payload, "")
	if clientIp != "" {
		return clientIp
	}
	return srcIp
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
	if len(result) < 2 {
		return ""
	}
	return result[1]
}
