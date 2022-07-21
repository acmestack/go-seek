/*
 * Copyright (c) 2022, AcmeStack
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package entity

type MonitorLog struct {
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
