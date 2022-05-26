package database

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"go-seek/pkg/httpinfo"
)

var dbGlobal *gorm.DB

func InitDb() {
	db, err := gorm.Open("mysql", "root:*@tcp(*:3306)/http_info?charset=utf8&parseTime=True&loc=Local")
	if err != nil {
		panic("连接数据库失败")
	}
	// 自动迁移模式
	db.AutoMigrate(&httpinfo.HttpBase{})
	dbGlobal = db
}

func ObtainDb() *gorm.DB {
	return dbGlobal
}
