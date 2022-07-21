/*
 * Copyright (c) 2022, AcmeStack
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package seek

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/acmestack/go-seek/common"
	"github.com/acmestack/go-seek/entity"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	snapshotLen int32 = 1024
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
)

var (
	businessSystemIdReg = "junSid=([0-9a-zA-Z]+)"
	userIdReg           = "junUid=([0-9a-zA-Z%]+)"
	machineIdReg        = "junMid=([0-9a-zA-Z]+)"
	extendedInfoReg     = "junExt=([0-9a-zA-Z{}]+)"
	urlReg              = "\\s(\\/.*)\\sHTTP"
	hostReg             = "Host:\\s(.*)"
	userAgentReg        = "User-Agent:\\s(.*)"
)

var seekConfig entity.SeekConfig

func StartSeek(config entity.SeekConfig) {
	seekConfig = config
	// 打印所有的所有的网卡
	devs, _ := pcap.FindAllDevs()
	for i, v := range devs {
		log.Println("索引：" + strconv.Itoa(i) + " 网卡名称：" + v.Name + " 网卡描述：" + v.Description)
	}

	// 监控网卡
	handle, err = pcap.OpenLive(seekConfig.Network, snapshotLen, false, timeout)
	if err != nil {
		log.Println("监控错误，请检查网卡是否配置正确：", seekConfig.Network)
		log.Fatal(err)
	}
	defer handle.Close()

	// 开始抓包
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	sendUrl := seekConfig.RemoteHost + seekConfig.SendUri

	for packet := range packetSource.Packets() {
		send(packet, sendUrl)
	}

}

func send(packet gopacket.Packet, sendUrl string) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		// 只抓取IPv4的数据
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
					dstPort = parseDstPort(dstPort)

					applicationLayer := packet.ApplicationLayer()
					if applicationLayer != nil {
						payload := string(applicationLayer.Payload())
						if isMonitorService(dstIP, dstPort) {
							url, marshal := getMonitorLog(payload, dstIP, dstPort, srcIp, tcp)
							if !isFiltering(url) && !isFilterIp(srcIp) {
								sendMonitorLog(sendUrl, marshal)
							}
						}
					}
				}
			}
		}
	}
}

func isMonitorService(dstIP string, dstPort string) bool {
	if dstIP == seekConfig.MonitorIp {
		ports := strings.Split(seekConfig.MonitorPorts, ",")
		for _, v := range ports {
			if strings.Contains(dstPort, v) {
				return true
			}
		}
	}
	return false
}

func parseDstPort(dstPort string) string {
	// 存在出现 80(http) 的可能所以需要切割一下
	if dstPort != "" {
		dstPort = strings.Split(dstPort, "(")[0]
	}
	return dstPort
}

func sendMonitorLog(sendUrl string, marshal []byte) {
	defaultClient := &http.Client{}
	response, err := defaultClient.Post(sendUrl, "application/json", strings.NewReader(string(marshal)))
	if err != nil {
		log.Println("推送失败：", err.Error())
		log.Println("检查地址是否正确：", sendUrl)
	}
	if response != nil {
		if response.StatusCode == 200 {
			log.Println("推送成功")
		} else {
			log.Println("推送失败：")
			log.Println("检查地址是否正确：", sendUrl)
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

func getMonitorLog(payload string, dstIP string, dstPort string, srcIp string, tcp *layers.TCP) (string, []byte) {
	sid := common.GetValueStringByRegex(payload, businessSystemIdReg)
	uid := common.GetValueStringByRegex(payload, userIdReg)
	mid := common.GetValueStringByRegex(payload, machineIdReg)
	ext := common.GetValueStringByRegex(payload, extendedInfoReg)
	url := getUrl(payload)
	ua := getUserAgent(payload)
	reqc := ""
	sa := dstIP + ":" + dstPort
	sd := getHost(payload)
	ct := time.Now().UnixMilli()
	reqt := time.Now().UnixMilli()
	t := 0
	dstIp := dstIP
	srcIp = getSrcIp(payload, srcIp)
	srcSeq := strconv.Itoa(int(tcp.Seq))
	log.Println("抓取数据：\n" + payload)
	monitorLog := entity.MonitorLog{
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
	marshal, _ := json.Marshal(monitorLog)
	log.Println("推送数据：")
	log.Println(string(marshal))
	log.Println("")
	return url, marshal
}

func getUrl(payload string) string {
	url := common.GetValueStringByRegex(payload, urlReg)
	host := common.GetValueStringByRegex(payload, hostReg)
	if host != "" {
		if strings.Contains(host, "\r") {
			host = host[0 : len(host)-1]
		}
		url = "http://" + host + url
		return url
	}
	return ""
}

func getHost(payload string) string {
	sd := common.GetValueStringByRegex(payload, hostReg)
	if sd != "" {
		if strings.Contains(sd, "\r") {
			sd = sd[0 : len(sd)-1]
			return sd
		}
	}
	return sd
}

func getUserAgent(payload string) string {
	ua := common.GetValueStringByRegex(payload, userAgentReg)
	if ua != "" {
		if strings.Contains(ua, "\r") {
			ua = ua[0 : len(ua)-1]
			return ua
		}
	}
	return ua
}

func isFiltering(url string) bool {
	if url == "" {
		return true
	}

	match, _ := regexp.Match(seekConfig.FilterFileReg, []byte(url))
	if match {
		log.Println("url该需要需要过滤：" + url)
	}
	return match
}

func isFilterIp(srcIp string) bool {
	filterIps := strings.Split(seekConfig.FilterIps, ",")
	for _, v := range filterIps {
		if srcIp == v {
			return true
		}
	}
	return false
}

func getSrcIp(payload string, srcIp string) string {
	clientIp := common.GetValueStringByRegex(payload, seekConfig.IpField)
	if clientIp != "" {
		if strings.Contains(clientIp, "\r") {
			clientIp = clientIp[0 : len(clientIp)-1]
			return clientIp
		}
	}
	return srcIp
}
