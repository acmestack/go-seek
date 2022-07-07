package httpinfo

type HttpBase struct {
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
