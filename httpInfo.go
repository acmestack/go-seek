package main

type HttpBase struct {
	Method    string
	Host      string
	UserAgent string
	Origin    string
	Referer   string
	Cookie    string
}

type httpCookie struct {
	token     string
	sessionID string
}
