package database

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"go-seek/pkg/httpinfo"
)

func InitDb() *gorm.DB {
	db, err := gorm.Open("mysql", "root:root-abcd-1234@tcp(123.57.13.246:3306)/http_info?charset=utf8&parseTime=True&loc=Local")
	if err != nil {
		panic("连接数据库失败")
	}
	// 自动迁移模式
	db.AutoMigrate(&httpinfo.HttpBase{})
	return db
}
