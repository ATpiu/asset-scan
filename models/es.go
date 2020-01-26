package models

import (
	"asset-scan/lib"
	"context"
	"fmt"
	"github.com/olivere/elastic"
	"time"
)

var result = `
{
	"properties": {
		"data": {
			"properties": {
				"ip": {
					"type": "ip",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"port": {
					"type": "integer",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"protocol": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"service": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"product": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"version": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"reason": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"nmap_starttime": {
					"type": "date"
				},
				"nmap_endtime": {
					"type": "date"
				},
				"nmap_time": {
					"type": "integer"
				},
				"masscan_starttime": {
					"type": "date"
				},
				"masscan_endtime": {
					"type": "date"
				},
				"masscan_time": {
					"type": "integer"
				}
			}
		},
		"time": {
			"type": "date"
		}
	}
}`

var scanhistory = `
{
	"properties": {
		"data": {
			"properties": {
				"starttime": {
					"type": "date",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"endtime": {
					"type": "date",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"scantime": {
					"type": "integer",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				}
			}
		},
		"time": {
			"type": "date"
		}
	}
}`

var addhistory = `
{
	"properties": {
		"addata": {
			"properties": {
				"ip": {
					"type": "ip",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"port": {
					"type": "integer",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"protocol": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"service": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"product": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"version": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				}
			}
		},
		"time": {
			"type": "date"
		}
	}
}
`

var uphistory = `
{
	"properties": {
		"updata": {
			"properties": {
				"ip": {
					"type": "ip",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"port": {
					"type": "integer",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"protocol": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"service": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"product": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"version": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"oldtime": {
					"type": "date",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				}
			}
		},
		"newdata": {
			"properties": {
				"ip": {
					"type": "ip",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"pott": {
					"type": "integer",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"protocol": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"service": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"product": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"version": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"uptime": {
					"type": "date",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				}
			}
		},
		"time": {
			"type": "date"
		}
	}
}
`

var bruteforce = `
{
	"properties": {
		"brutedata": {
			"properties": {
				"result": {
					"type": "boolean",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"ip": {
					"type": "ip",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"port": {
					"type": "integer",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"protocol": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"service": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"product": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"version": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"username": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"password": {
					"type": "text",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"starttime": {
					"type": "date",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				},
				"endtime": {
					"type": "date",
					"fields": {
						"keyword": {
							"type": "keyword"
						}
					}
				}
			}
		},
		"time": {
			"type": "date"
		}
	}
}
`

type EsData struct {
	dataType string
	data     EsSave
}
type EsSave struct {
	Data map[string]interface{} `json:"data"`
	Time string                 `json:"time"`
}

type EsUpData struct {
	dataType string
	data     EsUpSave
}
type EsUpSave struct {
	Data    map[string]interface{} `json:"updata"`
	NewData map[string]interface{} `json:"newdata"`
	Time    string                 `json:"time"`
}

type EsAddData struct {
	dataType string
	data     EsAddSave
}
type EsAddSave struct {
	AddData map[string]interface{} `json:"addata"`
	Time    string                 `json:"time"`
}

type EsBruteData struct {
	dataType string
	data     EsBruteSave
}
type EsBruteSave struct {
	Data map[string]interface{} `json:"brutedata"`
	Time string                 `json:"time"`
}

type Data struct {
	D Res    `json:"data"`
	T string `json:"time"`
}

type DataScanHistory struct {
	StartTime string `json:"starttime"`
	EndTime   string `json:"endtime"`
}

type ScanHistoryData struct {
	T DataScanHistory `json:"data"`
}

type Res struct {
	Ip             string `json:"ip"`
	Port           int    `json:"port"`
	Protocol       string `json:"protocol"`
	Service        string `json:"service"`
	Product        string `json:"product"`
	Version        string `json:"version"`
	Nmap_starttime string `json:"nmap_starttime"`
	Nmap_endtime   string `json:"nmap_endtime"`
}

var Client *elastic.Client
var esChan chan EsData
var esAddChan chan EsAddData
var esUpChan chan EsUpData
var esBruteChan chan EsBruteData

var nowIndex string

const Index = "scan-"

func Esinit(conf *Config) {
	var err error
	nowDate := time.Now().Local().Format("2006-01")
	nowIndex = Index + nowDate
	Client, err = elastic.NewClient(elastic.SetURL("http://" + conf.Es.Address))
	if err != nil {
		lib.FatalError(err.Error())
	}
	indexNameList, err := Client.IndexNames()
	if err != nil {
		lib.FatalError(err.Error())
	}
	if !judgeInArr(indexNameList, nowIndex) {
		newIndex(nowIndex)
	}
	esChan = make(chan EsData, 2048)
	esAddChan = make(chan EsAddData, 2048)
	esUpChan = make(chan EsUpData, 1024)
	esBruteChan = make(chan EsBruteData, 2048)

	go esCheckThread()
	go InsertThread()
}

func newIndex(name string) {
	var err error
	fmt.Println("[*]Init index", name)
	Client.CreateIndex(name).Do(context.Background())
	if _, err = Client.PutMapping().Index(name).Type("result").BodyString(result).Do(context.Background()); err != nil {
		lib.FatalError(err.Error())
	}
	_, err = Client.PutMapping().Index(name).Type("scanhistory").BodyString(scanhistory).Do(context.Background())
	if err != nil {
		lib.FatalError(err.Error())
	}
	_, err = Client.PutMapping().Index(name).Type("addhistory").BodyString(addhistory).Do(context.Background())
	if err != nil {
		lib.FatalError(err.Error())
	}
	_, err = Client.PutMapping().Index(name).Type("uphistory").BodyString(uphistory).Do(context.Background())
	if err != nil {
		lib.FatalError(err.Error())
	}
	_, err = Client.PutMapping().Index(name).Type("bruteforce").BodyString(bruteforce).Do(context.Background())
	if err != nil {
		lib.FatalError(err.Error())
	}
}

func isExist(ip string, port string, protocol string, service string, product string, version string, lastScanTime string, lastScanEndTime string) (bool, *elastic.SearchHit) {
	query := elastic.NewBoolQuery()
	if ip != "" {
		query.Must(elastic.NewTermQuery("data.ip", ip))
	}
	if port != "" {
		query.Must(elastic.NewMatchQuery("data.port", port))
	}
	if protocol != "" {
		query.Must(elastic.NewMatchQuery("data.protocol", protocol))
	}
	//if service != "" {
	//	query.Must(elastic.NewMatchQuery("data.service", service))
	//}
	//if product != "" {
	//	query.Must(elastic.NewMatchQuery("data.product", product))
	//}
	//if version != "" {
	//	query.Must(elastic.NewMatchQuery("data.version", version))
	//}
	if lastScanTime != "" && lastScanEndTime != "" {
		query.Must(elastic.NewRangeQuery("time").From(lastScanTime).To(lastScanEndTime))
	}
	res, err := Client.Search("scan*").Type("result").Query(query).Size(1).Do(context.Background())
	if err != nil {
		lib.FatalError(err.Error())
	}
	if res.TotalHits() > 0 {

		return true, res.Hits.Hits[0]
	}
	return false, nil
}

func InsertEs(dataType string, data EsSave) {
	esChan <- EsData{dataType, data}
}

func InsertEsAdd(dataType string, data EsAddSave) {
	esAddChan <- EsAddData{dataType, data}
}

func InsertEsUp(dataType string, upData EsUpSave) {
	esUpChan <- EsUpData{dataType, upData}
}

func InsertEsBrute(dataType string, data EsBruteSave) {
	esBruteChan <- EsBruteData{dataType, data}
}

func InsertThread() {
	var data EsData
	var addData EsAddData
	var upData EsUpData
	var bruteData EsBruteData

	p, err := Client.BulkProcessor().
		Name("Worker-1").
		Workers(2).
		BulkActions(100).
		BulkSize(2 << 20).
		FlushInterval(5 * time.Second).
		Do(context.Background())
	if err != nil {
		lib.FatalError(err.Error())
	}
	for {
		select {
		case data = <-esChan:
			p.Add(elastic.NewBulkIndexRequest().Index(nowIndex).Type(data.dataType).Doc(data.data))
		case addData = <-esAddChan:
			p.Add(elastic.NewBulkIndexRequest().Index(nowIndex).Type(addData.dataType).Doc(addData.data))
		case upData = <-esUpChan:
			p.Add(elastic.NewBulkIndexRequest().Index(nowIndex).Type(upData.dataType).Doc(upData.data))
		case bruteData = <-esBruteChan:
			p.Add(elastic.NewBulkIndexRequest().Index(nowIndex).Type(bruteData.dataType).Doc(bruteData.data))
			//default:
		}
	}
}

func esCheckThread() {
	ticker := time.NewTicker(time.Second * 3600)
	for range ticker.C {
		nowDate := time.Now().Local().Format("2006-01")
		nowIndex = Index + nowDate
		indexNameList, err := Client.IndexNames()
		if err != nil {
			continue
		}
		if judgeInArr(indexNameList, nowIndex) {
			if time.Now().Local().Day() >= 28 {
				nextData := time.Now().Local().AddDate(0, 1, 0).Format("2006_01")
				indicesName := Index + nextData
				if !judgeInArr(indexNameList, indicesName) {
					newIndex(indicesName)
				}
			}
		} else {
			newIndex(nowIndex)
		}
	}
}

func judgeInArr(list []string, value string) bool {
	for _, v := range list {
		if value == v {
			return true
		}
	}
	return false
}
