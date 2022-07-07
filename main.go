package main

import (
	"go-seek/pkg/seek"
	"log"
	"os"
)

func main() {
	strings := os.Args
	var deviceName string
	var dstIp string
	var remoteUrl string
	if len(strings) > 2 {
		deviceName = strings[1]
		dstIp = strings[2]
		remoteUrl = strings[3]
	} else {
		log.Println(
			`必须传入网卡名称，监控IP和推送地址:
                例如： go-seek eth0 192.168.3.31 http://192.168.3.104:6888/bsds/ajax/addServiceLogForJava
			`)
		return
	}
	log.Println("deviceName:", deviceName)
	log.Println("dstIp:", dstIp)
	log.Println("url:", remoteUrl)

	//deviceName = "\\Device\\NPF_{D108477B-204F-4BCB-991C-6906DF99FCE4}"
	//dstIp = "192.168.3.34"
	//remoteUrl = "http://192.168.3.104:6888/bsds/ajax/addServiceLogForJava"
	seek.StartSeek(deviceName, dstIp, remoteUrl)
	for true {

	}
}
