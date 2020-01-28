package models

import (
	"asset-scan/lib"
	"asset-scan/models/masscan"
	"asset-scan/models/nmap"
	"asset-scan/plugins"
	"context"
	"encoding/json"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Scanner struct {
	IpSet     *Set
	MTcp      *masscan.Masscan
	MUdp      *masscan.Masscan
	StartTime string
	EndTime   string
	Conf      *Config
	tcpCh     chan masscan.Host
	udpCh     chan masscan.Host
	wg        *sync.WaitGroup
	wgExist   *sync.WaitGroup
	wgBrute   *sync.WaitGroup
	isScan    bool
	UserList  []string
	PassList  []string
	Brutech   chan []nmap.NmapResult
}

type Scan struct {
	IpFile        string `yaml:"ipFile"`
	IpExcludeFile string `yaml:"ipexcludeFile"`
	UserList      string `yaml:"userDict"`
	PassList      string `yaml:"passwordDict"`
	ScanInterval  int    `yaml:"scan_interval"`
	Port          string `yaml:"port"`
}

type NmapScan struct {
	Path string `yaml:"path"`
}

type MasScan struct {
	Path string `yaml:"path"`
	Rate string `yaml:"rate"`
}

type Brute struct {
	StartTime string
	Ip        string
	Port      string
	Protocol  string
	Service   string
	Product   string
	Version   string
	Username  string
	Password  string
	Result    bool
	F         plugins.ScanType
	Cancel    context.CancelFunc
}

func (s *Scanner) ScanInit() {
	s.yamlCheck()
	s.tcpCh = make(chan masscan.Host, 2048)
	s.udpCh = make(chan masscan.Host, 2048)
}

func (s *Scanner) StartScan() (err error) {
	if s.isScan != true {
		s.isScan = true
		s.StartTime = lib.GetUnixTime()
		fmt.Println("[*]Start scan:", s.StartTime)

		lastScanTime, lastScanEndTime := s.GetLastScanTime("scanhistory")
		go s.MasDistribute(lastScanTime, lastScanEndTime)
		s.NmapDistribute()

		StartTime, _ := strconv.Atoi(s.StartTime)
		EndTime, _ := strconv.Atoi(s.EndTime)
		EsSaveData := EsSave{
			Data: map[string]interface{}{
				"starttime": StartTime,
				"endtime":   EndTime,
				"scantime":  fmt.Sprintf("%.2f", float64(EndTime)/1000-float64(StartTime)/1000),
			},
			Time: lib.GetUnixTime(),
		}
		fmt.Println("[*]End scan:", s.EndTime)
		InsertEs("scanhistory", EsSaveData)
		s.isScan = false
		time.Sleep(time.Second * 5)
	}
	return
}

func (s *Scanner) masscanInit(ip string) *masscan.Masscan {
	m := masscan.New()
	m.SetSystemPath(s.Conf.Masscan.Path)
	m.SetRate(s.Conf.Masscan.Rate)
	args := []string{
		"--wait", "0",
		"-p", s.Conf.S.Port,
		ip,
	}
	m.SetArgs(args...)
	return m
}

func (s *Scanner) nmapInit() *nmap.Nmap {
	n := nmap.New()
	n.SetSystemPath(s.Conf.Nmap.Path)
	args := []string{"-Pn", "", "-T4", "", "-n", "", "-open", "", "-oX", "-", "-sV", ""}
	n.SetArgs(args...)
	n.SetHostTimeOut("300000ms")
	return n
}

func (s *Scanner) NmapDistribute() {
	var (
		okTcp, isCompTcp bool
	)
	poolNmap := &ants.PoolWithFunc{}
	dataTcp := masscan.Host{}
	s.wg = &sync.WaitGroup{}

	poolNmap, _ = ants.NewPoolWithFunc(30, func(i interface{}) {
		defer s.wg.Done()
		results, _ := s.NmapRun(i.(masscan.Host).Address.Addr, i.(masscan.Host).Ports[0].Portid, i.(masscan.Host).Ports[0].Protocol)
		s.judgeExist(results, i.(masscan.Host))
		return
	})
	defer poolNmap.Release()

	for !(isCompTcp) {
		select {
		case dataTcp, okTcp = <-s.tcpCh:
			if okTcp {
				s.wg.Add(1)
				poolNmap.Invoke(dataTcp)
			} else {
				isCompTcp = true
			}

		default:
		}
	}
	s.wg.Wait()
	s.EndTime = lib.GetUnixTime()
}

func (s *Scanner) GetLastScanTime(dataType string) (string, string) {
	res, err := Client.Search("scan*").Type(dataType).Sort("time", false).Size(1).Do(context.Background())
	if err != nil {
		lib.FatalError(err.Error())
	}
	if res.TotalHits() == 0 {
		return "", ""
	}
	data := &ScanHistoryData{}
	for _, v := range res.Hits.Hits {
		if err := json.Unmarshal(*v.Source, &data); err != nil {
			fmt.Println(err)
		}
	}
	return data.T.StartTime, data.T.EndTime
}

func (s *Scanner) MasDistribute(lastScanTime string, lastScanEndTime string) {
	wg := &sync.WaitGroup{}
	pool, _ := ants.NewPoolWithFunc(30, func(i interface{}) {
		defer wg.Done()
		s.MasRun(i.(*masscan.Masscan))
		return
	})
	defer pool.Release()
	for ip := range s.IpSet.m {
		wg.Add(1)
		m := s.masscanInit(ip)
		m.LastScanTime = lastScanTime
		m.LastScanEndTime = lastScanEndTime
		pool.Invoke(m)
	}
	wg.Wait()
	close(s.tcpCh)
}

func (s *Scanner) MasRun(m *masscan.Masscan) {
	var err error
	if err = m.Run(); err != nil && !strings.Contains(err.Error(), "ranges overlapped something in an excludefile range") && !strings.Contains(err.Error(), "failed to detect router for interface") {
		lib.FatalError(err.Error())
	}
	resParse, _ := m.Parse()
	for _, res := range resParse {
		res.LastScanTime = m.LastScanTime
		res.LastScanEndTime = m.LastScanEndTime
		s.tcpCh <- res
	}
}

func (s *Scanner) NmapRun(ip string, port string, protocol string) ([]nmap.NmapResult, error) {
	results := make([]nmap.NmapResult, 1)
	var err error
	switch protocol {
	case "tcp":
		nTcp := s.nmapInit()
		nTcp.AppendSingleParma("-sS")
		nTcp.SetIpPorts(ip, port)
		nTcp.Run()
		results, _ = nTcp.Parse()
	case "udp":
		nUdp := s.nmapInit()
		nUdp.AppendSingleParma("-sU")
		nUdp.SetIpPorts(ip, port)
		nUdp.Run()
		results, _ = nUdp.Parse()
	}
	return results, err
}

//全量插入且检查最近的一次扫描中是否有相同记录
func (s *Scanner) judgeExist(results []nmap.NmapResult, m masscan.Host) {
	for _, v := range results {
		fmt.Println("--------------------------------")
		fmt.Println("Ip:" + v.Ip)
		fmt.Println("Port:", v.PortId)
		fmt.Println("Protocol:" + v.Protocol)
		fmt.Println("Service:" + v.Service)
		fmt.Println("Product:", v.Product)
		fmt.Println("Version:", v.Version)
		fmt.Println("masscan_starttime", m.StartTime)
		fmt.Println("masscan_endtime", m.Endtime)
		fmt.Println("nmap_starttime", v.StartTime)
		fmt.Println("nmap_endtime", v.EndTime)
		fmt.Println("lastScanTime:", m.LastScanTime)
		fmt.Println("lastScanEndTime:", m.LastScanEndTime)
		mStartTime, _ := strconv.Atoi(m.StartTime)
		mEndTime, _ := strconv.Atoi(m.Endtime)
		nStartTime, _ := strconv.Atoi(v.StartTime)
		nEndTime, _ := strconv.Atoi(v.EndTime)
		esSaveData := EsSave{
			Data: map[string]interface{}{
				"ip":                v.Ip,
				"port":              v.PortId,
				"protocol":          v.Protocol,
				"service":           v.Service,
				"product":           v.Product,
				"version":           v.Version,
				"masscan_starttime": m.StartTime,
				"masscan_endtime":   m.Endtime,
				"masscan_time":      fmt.Sprintf("%.2f", float64(mEndTime)/1000-float64(mStartTime)/1000),
				"nmap_starttime":    v.StartTime,
				"nmap_endtime":      v.EndTime,
				"nmap_time":         fmt.Sprintf("%.2f", float64(nEndTime)/1000-float64(nStartTime)/1000),
			},
			Time: lib.GetUnixTime(),
		}
		esAddData := EsAddSave{
			AddData: map[string]interface{}{
				"ip":                esSaveData.Data["ip"],
				"port":              esSaveData.Data["port"],
				"protocol":          esSaveData.Data["protocol"],
				"service":           esSaveData.Data["service"],
				"product":           esSaveData.Data["product"],
				"version":           esSaveData.Data["version"],
				"masscan_starttime": m.StartTime,
				"masscan_endtime":   m.Endtime,
				"masscan_time":      fmt.Sprintf("%.2f", float64(mEndTime)/1000-float64(mStartTime)/1000),
				"nmap_starttime":    v.StartTime,
				"nmap_endtime":      v.EndTime,
				"nmap_time":         fmt.Sprintf("%.2f", float64(nEndTime)/1000-float64(nStartTime)/1000),
			},
			Time: lib.GetUnixTime(),
		}
		//先持久化
		InsertEs("result", esSaveData)
		InsertEsAdd("addhistory", esAddData)
		//检查最近的一次扫描中是否有相同记录
		isExist, esTmp := isExist(v.Ip, strconv.Itoa(v.PortId), v.Protocol, v.Service, v.Product, v.Version, m.LastScanTime, m.LastScanEndTime)
		fmt.Println("isExist:", isExist)
		if isExist {
			data := &Data{}
			if err := json.Unmarshal(*esTmp.Source, &data); err != nil {
				fmt.Println(err)
			}
			upTime := lib.GetUnixTime()
			if data.D.Service != esSaveData.Data["service"] || data.D.Product != esSaveData.Data["product"] || data.D.Version != esSaveData.Data["version"] {
				esUpData := EsUpSave{
					Data: map[string]interface{}{
						"ip":       data.D.Ip,
						"port":     data.D.Port,
						"protocol": data.D.Protocol,
						"service":  data.D.Service,
						"product":  data.D.Product,
						"version":  data.D.Version,
						"oldtime":  data.T,
					},
					NewData: map[string]interface{}{
						"ip":       esSaveData.Data["ip"],
						"port":     esSaveData.Data["port"],
						"protocol": esSaveData.Data["protocol"],
						"service":  esSaveData.Data["service"],
						"product":  esSaveData.Data["product"],
						"version":  esSaveData.Data["version"],
						"uptime":   upTime,
					},
					Time: upTime,
				}
				InsertEsUp("uphistory", esUpData)
			}
		} else {
			//判断当前是否为观察模式
			if s.Conf.Observe.Sw != "on" {
				go SendMail(s.Conf.Mail, "[*]外网资产新增端口告警", "Ip: "+v.Ip+"<br>"+"Port: "+strconv.Itoa(v.PortId)+"<br>"+"Protocol: "+v.Protocol+"<br>"+"Service:"+v.Service+"<br>"+"Product: "+v.Product+"<br>"+"Version: "+v.Version+"<br>")
				s.Brutech <- results
			}
		}
	}
}
