package seek

import (
	"encoding/json"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"log"
	"net/http"
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
	filterFileReg       string = "(\\S*)\\.((css)|(js)|(png)|(gif)|(ico))\\b"
)

func StartSeek(name string, requestDstIp string, url string) {
	openSync(name, requestDstIp, url)
}

func openSync(deviceName string, requestDstIp string, remoteUrl string) {
	devs, _ := pcap.FindAllDevs()
	for _, v := range devs {
		log.Println("网卡名称：" + v.Name + " 网卡描述：" + v.Description)
	}

	handle, err = pcap.OpenLive(deviceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		send(packet, requestDstIp, remoteUrl)
	}
}

func send(packet gopacket.Packet, requestDstIp string, remoteUrl string) {
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

					// 存在出现 80(http) 的可能所以需要切割一下
					if dstPort != "" {
						dstPort = strings.Split(dstPort, "(")[0]
					}

					applicationLayer := packet.ApplicationLayer()
					if applicationLayer != nil {
						payload := string(applicationLayer.Payload())
						if dstIP == requestDstIp {
							sid := getOneStringByRegex(payload, businessSystemIdReg)
							uid := getOneStringByRegex(payload, userIdReg)
							mid := getOneStringByRegex(payload, machineIdReg)
							ext := getOneStringByRegex(payload, extendedInfoReg)
							url := getUrl(payload)
							ua := getOneStringByRegex(payload, userAgentReg)
							reqc := ""
							sa := dstIP + ":" + dstPort
							sd := getHost(payload)
							ct := time.Now().UnixMilli()
							reqt := time.Now().UnixMilli()
							t := 0
							dstIp := dstIP
							srcIp = getSrcIp(payload, srcIp)
							srcSeq := strconv.Itoa(int(tcp.Seq))
							log.Println(payload)
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
							log.Println(string(marshal))
							log.Println("")
							defaultClient := &http.Client{}
							if !isFiltering(url) {
								response, err := defaultClient.Post(remoteUrl, "application/json", strings.NewReader(string(marshal)))
								if err != nil {
									log.Println("推送失败：", err.Error())
									log.Println("检查地址是否正确：", remoteUrl)
								}
								if response != nil {
									if response.StatusCode == 200 {
										log.Println("推送成功")
									} else {
										log.Println("推送失败：")
										log.Println("检查地址是否正确：", remoteUrl)
									}
									log.Println("----------------------------------------------------------------------------------------------------------")
									defer func(Body io.ReadCloser) {
										err := Body.Close()
										if err != nil {
											log.Println(err)
										}
									}(response.Body)
								}
							}
						}
					}
				}
			}
		}
	}
}

func getHost(payload string) string {
	sd := getOneStringByRegex(payload, hostReg)
	if sd != "" {
		if strings.Contains(sd, "\r") {
			sd = sd[0 : len(sd)-1]
			return sd
		}
	}
	return sd
}

func isFiltering(url string) bool {
	match, _ := regexp.Match(filterFileReg, []byte(url))
	if match {
		log.Println("url该需要需要过滤：" + url)
	}
	return match
}

func getUrl(payload string) string {
	url := getOneStringByRegex(payload, urlReg)
	host := getOneStringByRegex(payload, hostReg)
	if host != "" {
		if strings.Contains(host, "\r") {
			host = host[0 : len(host)-1]
		}
		url = "http://" + host + url
		return url
	}
	return ""
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
