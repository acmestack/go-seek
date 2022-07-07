package seek

type MongoServiceLog struct {
	Oid             string `json:"oid"`
	T               int    `json:"t"`
	Sid             string `json:"sid"`
	Sd              string `json:"sd"`
	Sa              string `json:"sa"`
	Uid             string `json:"uid"`
	Duid            string `json:"duid"`
	Mid             string `json:"mid"`
	Url             string `json:"url"`
	Reqt            int64  `json:"reqt"`
	Reqc            string `json:"reqc"`
	SrcIp           string `json:"src_ip"`
	DstIp           string `json:"dst_ip"`
	SrcSeq          string `json:"src_seq"`
	DstAck          string `json:"dst_ack"`
	Rest            string `json:"rest"`
	Resc            string `json:"resc"`
	Reslen          string `json:"reslen"`
	Ua              string `json:"ua"`
	Ext             string `json:"ext"`
	Ct              int64  `json:"ct"`
	Urlmd5          string `json:"urlmd5"`
	BehaviorId      string `json:"behavior_id"`
	Behavior        string `json:"behavior"`
	RequestSystemId string
}
