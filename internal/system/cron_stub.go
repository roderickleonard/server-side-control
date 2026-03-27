//go:build !linux

package system

import "fmt"

func ListCronJobs(user string) ([]CronJob, error) {
	return nil, fmt.Errorf("cron management is only supported on Ubuntu target hosts")
}

func CreateCronJob(spec CronJobSpec) (string, error) {
	return "", fmt.Errorf("cron management is only supported on Ubuntu target hosts")
}

func UpdateCronJob(spec CronJobUpdateSpec) (string, error) {
	return "", fmt.Errorf("cron management is only supported on Ubuntu target hosts")
}

func DeleteCronJob(spec CronJobDeleteSpec) (string, error) {
	return "", fmt.Errorf("cron management is only supported on Ubuntu target hosts")
}

func ClearCronJobLog(user string, id string) (string, error) {
	return "", fmt.Errorf("cron management is only supported on Ubuntu target hosts")
}

func RotateCronJobLog(user string, id string) (string, error) {
	return "", fmt.Errorf("cron management is only supported on Ubuntu target hosts")
}