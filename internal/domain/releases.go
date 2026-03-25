package domain

import "time"

type DeploymentRelease struct {
	ID                int64
	RepositoryURL     string
	BranchName        string
	TargetDirectory   string
	RunAsUser         string
	Action            string
	Status            string
	CommitSHA         string
	PreviousCommitSHA string
	Output            string
	CreatedAt         time.Time
}
