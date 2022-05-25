package main

import "github.com/jinzhu/gorm"

type HttpBase struct {
	gorm.Model
	Method    string
	Host      string
	UserAgent string
	Origin    string
	Referer   string
	Cookie    string
}

type HttpCookie struct {
	token     string
	sessionID string
}
