package main

import (
	"encoding/json"
	"fmt"
	"github.com/spf13/viper"
	"junan-bsds-seek-go/entity"
	"junan-bsds-seek-go/seek"
	"log"
)

func main() {
	seekConfig := getSeekConfig()
	seek.StartSeek(seekConfig)
}

func initConfig() {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("config")
	err := viper.ReadInConfig()
	if err != nil {
		if v, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println(v)
		} else {
			panic(fmt.Errorf("read config err=%s", err))
		}
	}
}

func getSeekConfig() entity.SeekConfig {
	initConfig()
	var seekConfig entity.SeekConfig
	remoteHost := viper.GetString("remote-host")
	sendUri := viper.GetString("send-uri")
	monitorIp := viper.GetString("monitor-ip")
	monitorPorts := viper.GetString("monitor-ports")
	network := viper.GetString("network")
	ipField := viper.GetString("ip-field")
	filterFileReg := viper.GetString("filter-file-reg")
	filterIps := viper.GetString("filter-ips")

	seekConfig.RemoteHost = remoteHost
	seekConfig.SendUri = sendUri
	seekConfig.MonitorIp = monitorIp
	seekConfig.MonitorPorts = monitorPorts
	seekConfig.Network = network
	seekConfig.IpField = ipField
	seekConfig.FilterFileReg = filterFileReg
	seekConfig.FilterIps = filterIps
	marshal, _ := json.Marshal(seekConfig)
	log.Println("读取配置文件结果：\n", string(marshal))
	return seekConfig
}
