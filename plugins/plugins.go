package plugins

type ScanType func(ip string, port string, username string, password string) (err error, result bool)

var ScanTypeMap map[string]ScanType

func init() {
	ScanTypeMap = make(map[string]ScanType, 0)
	ScanTypeMap["ftp"] = ScanFtp
	ScanTypeMap["mongod"] = ScanMongodb
	ScanTypeMap["ms-sql-s"] = ScanMssql
	ScanTypeMap["mysql"] = ScanMysql
	ScanTypeMap["postgresql"] = ScanPostgres
	ScanTypeMap["redis"] = ScanRedis
	ScanTypeMap["ssh"] = ScanSsh
}
