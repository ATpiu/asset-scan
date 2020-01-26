package plugins_test

import (
	"asset-scan/plugins"
	"testing"
)

func TestScanMysql(t *testing.T) {
	t.Log(plugins.ScanMysql("127.0.0.1", "3306", "root", "123456"))
}
