package models

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"strconv"
	"strings"
)

type Empty struct{}
type Set struct {
	m map[string]Empty
}

//将ip段(192.168.1.0/24,192.168.2.3-5)转换成ip数组(192.168.1.1,192.168.1.2,...,192.168.2.5)
func (s *Set) ProcessIp(ipFile string, ipFileEx string) {
	s.Add(processIpAll(fileToArr(ipFile))...)
	s.Remove(processIpAll(fileToArr(ipFileEx))...)
}

func processIpAll(ipArr []string) []string {
	var arr []string
	for _, ip := range ipArr {
		arr = append(arr, processIpItem(ip)...)
	}
	return arr
}

func processIpItem(ip string) []string {
	if strings.Contains(ip, "/") {
		_, ipNet, _ := net.ParseCIDR(ip)
		return IPRange(ipNet)
	} else if strings.Contains(ip, "-") {
		var ips []string
		arr := strings.Split(ip, ".")
		for _, a := range rangeToArr(arr[0]) {
			for _, b := range rangeToArr(arr[1]) {
				for _, c := range rangeToArr(arr[2]) {
					for _, d := range rangeToArr(arr[3]) {
						IP := a + "." + b + "." + c + "." + d
						ips = append(ips, IP)
					}
				}
			}
		}
		return ips
	} else {
		return []string{ip}
	}
}

//convert "1-3" to ["1", "2", "3"]
func rangeToArr(s string) []string {
	if strings.Contains(s, "-") {
		var arr []string
		from, _ := strconv.Atoi(strings.Split(s, "-")[0])
		to, _ := strconv.Atoi(strings.Split(s, "-")[1])
		if from == 0 {
			from = 1
		}
		if to == 0 {
			to = 65535
		}
		for i := from; i <= to; i++ {
			arr = append(arr, strconv.Itoa(i))
		}
		return arr
	} else {
		return []string{s}
	}
}

//从文件读取ip段
func fileToArr(path string) []string {
	if path == "" {
		return []string{}
	}
	f, err := ioutil.ReadFile(path)
	if err != nil {
		panic(err)
	}
	arr := strings.Split(strings.Replace(string(f), "\r", "", -1), "\n")
	for key, val := range arr {
		arr[key] = strings.TrimSpace(val)
	}
	return arr
}

//获取一个集合实例
func NewIpSet() *Set {
	return &Set{
		m: map[string]Empty{},
	}
}

//添加元素
func (s *Set) Add(val ...string) {
	var empty Empty
	for _, elem := range val {
		s.m[elem] = empty
	}
}

//删除元素
func (s *Set) Remove(val ...string) {
	for _, elem := range val {
		delete(s.m, elem)
	}
}

//获取长度
func (s *Set) Len() int {
	return len(s.m)
}

//清空set
func (s *Set) Clear() {
	s.m = make(map[string]Empty)
}

//遍历集合
func (s *Set) Traverse() {
	for i := range s.m {
		fmt.Println(i)
	}
}

type IP uint32

// 将 IP(uint32) 转换成 可读性IP字符串
func (ip IP) String() string {
	var bf bytes.Buffer
	for i := 1; i <= 4; i++ {
		bf.WriteString(strconv.Itoa(int((ip >> ((4 - uint(i)) * 8)) & 0xff)))
		if i != 4 {
			bf.WriteByte('.')
		}
	}
	return bf.String()
}

// 根据IP和mask换算内网IP范围
func IPRange(ipNet *net.IPNet) []string {
	ip := ipNet.IP.To4()
	//log.Info("本机ip:", ip)
	var min, max IP
	var data []string
	for i := 0; i < 4; i++ {
		b := IP(ip[i] & ipNet.Mask[i])
		min += b << ((3 - uint(i)) * 8)
	}
	one, _ := ipNet.Mask.Size()
	max = min | IP(math.Pow(2, float64(32-one))-1)
	for i := min; i < max; i++ {
		if i&0x000000ff == 0 {
			continue
		}
		data = append(data, i.String())
	}
	return data
}

// []byte --> IP
func ParseIP(b []byte) IP {
	return IP(IP(b[0])<<24 + IP(b[1])<<16 + IP(b[2])<<8 + IP(b[3]))
}
