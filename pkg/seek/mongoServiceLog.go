package seek

import "time"

type MongoServiceLog struct {
	Oid             string
	T               int
	Sid             string
	Sd              string
	Sa              string
	Uid             string
	Duid            string
	Mid             string
	Url             string
	Reqt            time.Time
	Reqc            string
	SrcIp           string
	DstIp           string
	SrcSeq          string
	DstAck          string
	Rest            string
	Resc            string
	Reslen          string
	Ua              string
	Ext             string
	Ct              time.Time
	Urlmd5          string
	BehaviorId      string
	Behavior        string
	RequestSystemId string
}
