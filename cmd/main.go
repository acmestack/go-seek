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

package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/acmestack/go-seek/entity"
	"github.com/acmestack/go-seek/seek"
	"github.com/spf13/viper"
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
