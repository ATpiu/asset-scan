package lib

import (
	"log"
	"net"
	"runtime"
	"strconv"
	"time"
)

func GetUnixTime() string {
	return strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
}

func CheckSystem() {
	if runtime.GOOS != "linux" {
		FatalError("[*]目前仅支持Linux系统")
	}
}

func FatalError(err string) {
	log.Fatal(err)
}

func TCPSend(ip string, port string, data []byte) (error, []byte) {
	var err error
	conn, err := net.DialTimeout("tcp", ip+":"+port, time.Second*time.Duration(3))
	if err != nil {
		return err, nil
	}
	defer conn.Close()
	_, err = conn.Write(data)
	if err != nil {
		return err, nil
	}
	buf := make([]byte, 20000)
	n, err := conn.Read(buf)
	if err != nil {
		return err, nil
	}
	return nil, buf[:n]
}
