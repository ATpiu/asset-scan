package models

import (
	"asset-scan/lib"
	"bufio"
	"gopkg.in/yaml.v2"
	"os"
	"runtime"
)

type Config struct {
	Ver     string   `yaml:"version"`
	Nmap    NmapScan `yaml:"nmap"`
	Masscan MasScan  `yaml:"masscan"`
	S       Scan     `yaml:"scan"`
	Mail    Mail     `yaml:"mail"`
	Es      Es       `yaml:"es"`
	Observe Observe  `yaml:"observe"`
}

type Observe struct {
	Sw string `yaml:"switch"`
}

type Es struct {
	Address string `yaml:"address"`
}

type Mail struct {
	Host     string   `yaml:"host"`
	Port     int      `yaml:"port"`
	Username string   `yaml:"username"`
	Passwrod string   `yaml:"password"`
	From     string   `yaml:"from"`
	To       []string `yaml:",flow"`
}

func ReadYamlConfig(path string) (conf *Config, err error) {
	conf = &Config{}
	f := &os.File{}
	if f, err = os.Open(path); err != nil {
		return
	}
	yaml.NewDecoder(f).Decode(conf)
	return
}

func (s *Scanner) yamlCheck() {
	var err error
	//config.yaml解析
	dir, _ := os.Getwd()
	yamlPath := dir + "/config.yaml"
	if s.Conf, err = ReadYamlConfig(yamlPath); err != nil {
		lib.FatalError(err.Error())
	}
	if s.Conf.Masscan.Path == "" {
		s.Conf.Masscan.Path = "masscan"
	}
	if s.Conf.Nmap.Path == "" {
		s.Conf.Nmap.Path = "nmap"
	}
	//扫描和排除ip段解析 todo:nmap格式校验
	s.IpSet = NewIpSet()
	s.IpSet.ProcessIp(s.Conf.S.IpFile, s.Conf.S.IpExcludeFile)
	//字典解析
	s.UserList = make([]string, 0)
	s.PassList = make([]string, 0)
	if err := s.ReadUserPass(); err != nil {
		lib.FatalError(err.Error())
	}
}

func (s *Scanner) ReadUserPass() (err error) {
	user, err := os.Open(s.Conf.S.UserList)
	if err != nil {
		return
	}
	defer user.Close()
	userScanner := bufio.NewScanner(user)
	for userScanner.Scan() {
		s.UserList = append(s.UserList, userScanner.Text()) //todo:可能存在问题
	}

	pass, err := os.Open(s.Conf.S.PassList)
	if err != nil {
		return
	}
	defer pass.Close()
	passScanner := bufio.NewScanner(pass)
	for passScanner.Scan() {
		s.PassList = append(s.PassList, passScanner.Text()) //todo:可能存在问题
	}
	runtime.GC()
	return
}
