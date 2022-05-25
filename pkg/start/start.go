package start

import (
	"go-seek/pkg/database"
	"go-seek/pkg/seek"
	"go-seek/pkg/web"
)

func Start() {
	go seek.StartSeek()
	database.InitDb()
	web.StartWeb()
}
