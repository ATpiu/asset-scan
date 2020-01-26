package models

import (
	"asset-scan/lib"
	"asset-scan/models/nmap"
	"asset-scan/plugins"
	"context"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"strconv"
	"strings"
	"sync"
)

func (s *Scanner) bruteRun(brute Brute) {
	var err error
	var result bool
	EsBruteData := EsBruteSave{
		Data: map[string]interface{}{
			"starttime": brute.StartTime,
			"endtime":   lib.GetUnixTime(),
			"ip":        brute.Ip,
			"port":      brute.Port,
			"protocol":  brute.Protocol,
			"service":   brute.Service,
			"product":   brute.Product,
			"version":   brute.Version,
			"result":    "false",
		},
		Time: lib.GetUnixTime(),
	}
	if err, result = brute.F(brute.Ip, brute.Port, brute.Username, brute.Password); err == nil && result == true {
		EsBruteData.Data["result"] = "true"
		EsBruteData.Data["username"] = brute.Username
		EsBruteData.Data["password"] = brute.Password
		fmt.Println("[*]新增资产服务暴力破解成功")
		fmt.Println("Ip: " + brute.Ip + " " + "Port: " + brute.Port + " " + "Protocol: " + brute.Protocol + " " + "Service:" + brute.Service + " " + "Product: " + brute.Product + " " + "Version: " + brute.Version)
		go SendMail(s.Conf.Mail, "[*]新增资产服务暴力破解成功", "Ip: "+brute.Ip+"<br>"+"Port: "+brute.Port+"<br>"+"Protocol: "+brute.Protocol+"<br>"+"Service:"+brute.Service+"<br>"+"Product: "+brute.Product+"<br>"+"Version: "+brute.Version+"<br>"+"username: "+brute.Username+"<br>"+"password: "+brute.Password+"<br>")
		InsertEsBrute("bruteforce", EsBruteData)
		brute.Cancel()
	}

}

func (s *Scanner) unauth(ip string, port string, protocol string, service string, product string, version string) bool {
	time := lib.GetUnixTime()
	EsSaveData := EsSave{
		Data: map[string]interface{}{
			"starttime": time,
			"endtime":   time,
			"ip":        ip,
			"port":      port,
			"protocol":  protocol,
			"service":   service,
			"product":   product,
			"version":   version,
			"result":    "false",
		},
		Time: lib.GetUnixTime(),
	}
	switch service {
	case "mongod":
		if _, res := plugins.MongoUnauth(ip, port); res {
			EsSaveData.Data["result"] = "true"
			EsSaveData.Data["username"] = ""
			EsSaveData.Data["password"] = ""
			fmt.Println("Ip: " + ip + " " + "Port: " + port + " " + "Protocol: " + protocol + " " + "Service:" + service + " " + "Product: " + product + " " + "Version: " + version)
			go SendMail(s.Conf.Mail, "[*]新增资产服务暴力破解成功", "Ip: "+ip+"<br>"+"Port: "+port+"<br>"+"Protocol: "+protocol+"<br>"+"Service:"+service+"<br>"+"Product: "+product+"<br>"+"Version: "+version+"<br>"+"username: "+""+"<br>"+"password: "+""+"<br>")
			InsertEs("bruteforce", EsSaveData)
			return true
		}
	case "redis":
		if _, res := plugins.ScanRedis(ip, port, "", ""); res {
			EsSaveData.Data["result"] = "true"
			EsSaveData.Data["username"] = ""
			EsSaveData.Data["password"] = ""
			fmt.Println("Ip: " + ip + " " + "Port: " + port + " " + "Protocol: " + protocol + " " + "Service:" + service + " " + "Product: " + product + " " + "Version: " + version)
			go SendMail(s.Conf.Mail, "[*]新增资产服务暴力破解成功", "Ip: "+ip+"<br>"+"Port: "+port+"<br>"+"Protocol: "+protocol+"<br>"+"Service:"+service+"<br>"+"Product: "+product+"<br>"+"Version: "+version+"<br>"+"username: "+""+"<br>"+"password: "+""+"<br>")
			InsertEs("bruteforce", EsSaveData)
			return true
		}
	case "memcached":
		err, res := lib.TCPSend(ip, port, []byte("stats\r\n"))
		if err == nil && strings.Contains(string(res), "STAT version") {
			EsSaveData.Data["result"] = "true"
			EsSaveData.Data["username"] = ""
			EsSaveData.Data["password"] = ""
			fmt.Println("Ip: " + ip + " " + "Port: " + port + " " + "Protocol: " + protocol + " " + "Service:" + service + " " + "Product: " + product + " " + "Version: " + version)
			go SendMail(s.Conf.Mail, "[*]新增资产服务暴力破解成功", "Ip: "+ip+"<br>"+"Port: "+port+"<br>"+"Protocol: "+protocol+"<br>"+"Service:"+service+"<br>"+"Product: "+product+"<br>"+"Version: "+version+"<br>"+"username: "+""+"<br>"+"password: "+""+"<br>")
			InsertEs("bruteforce", EsSaveData)
			return true
		}
	default:
	}
	return false
}

func (s *Scanner) BruteForce() {
	s.Brutech = make(chan []nmap.NmapResult, 100)
	pool, _ := ants.NewPoolWithFunc(100, func(i interface{}) {
		defer s.wgBrute.Done()
		s.bruteRun(i.(Brute))
		return
	})
	for {
		fmt.Println("[*]Wait brute")
		target := <-s.Brutech
		//未授权访问测试
		if res := s.unauth(target[0].Ip, strconv.Itoa(target[0].PortId), target[0].Protocol, target[0].Service, target[0].Product, target[0].Version); res {
			break
		}
		var isComplete bool
		s.yamlCheck()
		if f, ok := plugins.ScanTypeMap[target[0].Service]; ok {
			fmt.Println("[*]Start brute:\n", target[0].Ip+":"+strconv.Itoa(target[0].PortId)+"-->", target[0].Service)
			ctx, cancel := context.WithCancel(context.Background())
			bruteList, num := s.GenerateList(target, f, cancel, lib.GetUnixTime())
			s.wgBrute = &sync.WaitGroup{}
			i := 0
			for !isComplete {
				select {
				case <-ctx.Done():
					isComplete = true
					break
				default:
					if i < num {
						pool.Invoke(bruteList[i])
						s.wgBrute.Add(1)
						i++
					} else {
						s.wgBrute.Wait()

						isComplete = true
						break
					}
				}
			}
		}
	}
}

func (s *Scanner) GenerateList(target []nmap.NmapResult, f plugins.ScanType, cancel context.CancelFunc, startTime string) (brute []Brute, num int) {
	for _, user := range s.UserList {
		for _, pass := range s.PassList {
			b := Brute{
				StartTime: startTime,
				Ip:        target[0].Ip,
				Port:      strconv.Itoa(target[0].PortId),
				Protocol:  target[0].Protocol,
				Service:   target[0].Service,
				Product:   target[0].Product,
				Version:   target[0].Version,
				Username:  user,
				Password:  pass,
				F:         f,
				Cancel:    cancel,
			}
			brute = append(brute, b)
		}
	}
	return brute, len(brute)
}
