//
//   date  : 2014-06-04
//   author: xjdrew
//

package tunnel

import (
	"sync/atomic"
	"time"
)

const (
	TunnelMaxId = ^uint16(0)

	TunnelPacketSize      = 8192
	TunnelKeepAlivePeriod = time.Second * 180

	defaultHeartbeat = 1
	tunnelMinSpan    = 3 // 3次心跳无回应则断开
)

// 使用 atomic 操作保证并发安全的配置变量
var (
	heartbeat atomic.Int32 // 单位：秒
	timeout   atomic.Int32 // 单位：秒
	logLevel  atomic.Uint32

	mpool = NewMPool(TunnelPacketSize)

	// Heartbeat / Timeout / LogLevel 供 flag 包绑定（兼容旧接口）
	Heartbeat int  = 1
	Timeout   int  = 0
	LogLevel  uint = 1
)

func init() {
	heartbeat.Store(1)
	timeout.Store(0)
	logLevel.Store(1)
}

// SetHeartbeat 更新心跳间隔（秒）
func SetHeartbeat(seconds int) {
	if seconds <= 0 {
		seconds = defaultHeartbeat
	}
	heartbeat.Store(int32(seconds))
}

func getHeartbeat() time.Duration {
	v := heartbeat.Load()
	if v <= 0 {
		v = defaultHeartbeat
	}
	return time.Duration(v) * time.Second
}

// SetTimeout 更新读写超时（秒）
func SetTimeout(seconds int) {
	timeout.Store(int32(seconds))
}

func getTimeout() time.Duration {
	return time.Duration(timeout.Load()) * time.Second
}

// SetLogLevel 更新日志级别
func SetLogLevel(level uint) {
	logLevel.Store(uint32(level))
}

func getLogLevel() uint {
	return uint(logLevel.Load())
}
