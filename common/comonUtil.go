package common

import (
	"regexp"
)

func GetValueStringByRegex(str, rule string) string {
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
