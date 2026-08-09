package main

import "encoding/json"

type inbound struct {
	ID                   int             `json:"id"`
	Up                   int64           `json:"up"`
	Down                 int64           `json:"down"`
	Total                int64           `json:"total"`
	Remark               string          `json:"remark"`
	SubSortIndex         int             `json:"subSortIndex"`
	Enable               bool            `json:"enable"`
	ExpiryTime           int64           `json:"expiryTime"`
	TrafficReset         string          `json:"trafficReset,omitempty"`
	TrafficResetDay      int             `json:"trafficResetDay,omitempty"`
	LastTrafficResetTime int64           `json:"lastTrafficResetTime,omitempty"`
	ClientStats          []clientTraffic `json:"clientStats"`
	Listen               string          `json:"listen"`
	Port                 int             `json:"port"`
	Protocol             string          `json:"protocol"`
	Settings             string          `json:"settings"`
	StreamSettings       string          `json:"streamSettings"`
	Tag                  string          `json:"tag"`
	Sniffing             string          `json:"sniffing"`
	ShareAddrStrategy    string          `json:"shareAddrStrategy"`
	ShareAddr            string          `json:"shareAddr"`
}

type inboundRecord struct {
	Inbound inbound                    `json:"inbound"`
	Service string                     `json:"service"`
	Extra   map[string]json.RawMessage `json:"extra,omitempty"`
}

type client struct {
	ID           string          `json:"id,omitempty"`
	Security     string          `json:"security,omitempty"`
	Password     string          `json:"password,omitempty"`
	Flow         string          `json:"flow,omitempty"`
	Reverse      json.RawMessage `json:"reverse,omitempty"`
	Auth         string          `json:"auth,omitempty"`
	PrivateKey   string          `json:"privateKey,omitempty"`
	PublicKey    string          `json:"publicKey,omitempty"`
	AllowedIPs   []string        `json:"allowedIPs,omitempty"`
	PreSharedKey string          `json:"preSharedKey,omitempty"`
	KeepAlive    int             `json:"keepAlive,omitempty"`
	Secret       string          `json:"secret,omitempty"`
	AdTag        string          `json:"adTag,omitempty"`
	Email        string          `json:"email"`
	LimitIP      int             `json:"limitIp"`
	TotalGB      int64           `json:"totalGB"`
	ExpiryTime   int64           `json:"expiryTime"`
	Enable       bool            `json:"enable"`
	TgID         int64           `json:"tgId"`
	SubID        string          `json:"subId"`
	Group        string          `json:"group,omitempty"`
	Comment      string          `json:"comment"`
	Reset        int             `json:"reset"`
}

type clientTraffic struct {
	ID         int    `json:"id"`
	InboundID  int    `json:"inboundId"`
	Enable     bool   `json:"enable"`
	Email      string `json:"email"`
	UUID       string `json:"uuid,omitempty"`
	SubID      string `json:"subId,omitempty"`
	Up         int64  `json:"up"`
	Down       int64  `json:"down"`
	ExpiryTime int64  `json:"expiryTime"`
	Total      int64  `json:"total"`
	Reset      int    `json:"reset"`
	LastOnline int64  `json:"lastOnline"`
}

type state struct {
	NextID     int                          `json:"nextId"`
	Inbounds   []inboundRecord              `json:"inbounds"`
	KnownTags  map[string][]string          `json:"knownTags"`
	LastOnline map[string]int64             `json:"lastOnline"`
	TagRenames map[string]map[string]string `json:"-"`
}

type envelope struct {
	Success bool   `json:"success"`
	Msg     string `json:"msg"`
	Obj     any    `json:"obj"`
}

func rawJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
