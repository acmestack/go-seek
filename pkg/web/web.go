package web

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"github.com/jinzhu/gorm"
	"go-seek/pkg/database"
	"go-seek/pkg/httpinfo"
	"net/http"
	"strconv"
	"time"
)

func StartWeb() {
	engine := gin.Default()
	db := database.ObtainDb()

	// 获取所有数据
	engine.GET("/findAll", func(c *gin.Context) {
		var httpBases []httpinfo.HttpBase
		httpBasesResult := db.Find(&httpBases)
		httpBasesResultJson, _ := json.Marshal(httpBasesResult.Value)
		c.String(http.StatusOK, string(httpBasesResultJson))
	})

	// 删除数据
	engine.DELETE("/delete/:id", func(c *gin.Context) {
		id := c.Param("id")
		atoi, _ := strconv.Atoi(id)
		uid := uint(atoi)
		db.Delete(&httpinfo.HttpBase{Model: gorm.Model{ID: uid}})
		c.String(http.StatusOK, "删除成功！")
	})

	// 添加数据
	engine.POST("/add", func(c *gin.Context) {
		var httpBase httpinfo.HttpBase
		if err := c.ShouldBindJSON(&httpBase); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		httpBase.CreatedAt = time.Now()
		httpBase.UpdatedAt = time.Now()
		db.Create(&httpBase)
		c.String(http.StatusOK, "创建成功！")
	})

	// 修改数据
	engine.PUT("/edit", func(c *gin.Context) {
		var httpBase httpinfo.HttpBase
		if err := c.ShouldBindJSON(&httpBase); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		}
		httpBase.UpdatedAt = time.Now()
		db.Model(&httpBase).Debug().Updates(httpBase)
		c.String(http.StatusOK, "修改成功！")
	})

	engine.Run(":9097")
}
