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
