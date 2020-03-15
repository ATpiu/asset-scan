package main

import (
	"asset-scan/lib"
	"asset-scan/models"
	"time"
	)

func init() {
	lib.CheckSystem()
}

func main() {
	s := &models.Scanner{
		Conf: &models.Config{},
	}
	s.ScanInit()
	models.Esinit(s.Conf)
	go s.BruteForce()
	ticker := time.NewTicker(time.Second * time.Duration(s.Conf.S.ScanInterval))
	defer ticker.Stop()
	for {
		s.ScanInit()
		if err := s.StartScan(); err != nil {
			lib.FatalError(err.Error())
		}
		<-ticker.C
	}
}
