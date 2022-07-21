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

package entity

type SeekConfig struct {

	// 远程IP
	RemoteHost string

	// 过滤规则地址
	SendUri string

	// 过滤规则地址
	RuleUri string

	// 更新规则时间
	UpdateRuleTime string

	// 监听IP
	MonitorIp string

	// 监听端口，逗号分割
	MonitorPorts string

	// 网卡
	Network string

	// 网卡索引
	NetworkIndex int

	// 系统Id
	SystemIds string

	// 网关IP字段名
	IpField string

	// 需要过滤的文件后缀正则
	FilterFileReg string

	// 过滤IP
	FilterIps string
}
