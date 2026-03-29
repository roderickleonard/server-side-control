//go:build !linux

package system

import "fmt"

type stubRedisManager struct{}

func NewRedisManager() RedisManager {
	return stubRedisManager{}
}

func (stubRedisManager) Inspect() (RedisStatus, error) {
	return RedisStatus{}, fmt.Errorf("redis management is only supported on Ubuntu target hosts")
}

func (stubRedisManager) Install() (string, error) {
	return "", fmt.Errorf("redis management is only supported on Ubuntu target hosts")
}

func (stubRedisManager) Configure(spec RedisConfigSpec) (string, error) {
	return "", fmt.Errorf("redis management is only supported on Ubuntu target hosts")
}

func (stubRedisManager) Start() (string, error) {
	return "", fmt.Errorf("redis management is only supported on Ubuntu target hosts")
}

func (stubRedisManager) Stop() (string, error) {
	return "", fmt.Errorf("redis management is only supported on Ubuntu target hosts")
}

func (stubRedisManager) Restart() (string, error) {
	return "", fmt.Errorf("redis management is only supported on Ubuntu target hosts")
}

func (stubRedisManager) TestConnection(spec RedisPingSpec) (string, error) {
	return "", fmt.Errorf("redis management is only supported on Ubuntu target hosts")
}

func (stubRedisManager) Logs(lines int) (string, error) {
	return "", fmt.Errorf("redis management is only supported on Ubuntu target hosts")
}