package plugins

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"time"
)

func ScanMysql(ip string, port string, username string, password string) (err error, result bool) {
	connStr := fmt.Sprintf("%s:%s@tcp(%s)/?timeout=%ds", username, password, ip+":"+port, time.Second*3)
	db, err := sql.Open("mysql", connStr)
	if err == nil {
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result = true
		}
	}
	return err, result
}
