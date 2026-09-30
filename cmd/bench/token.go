package main

import (
	"time"

	"pnc3-gateway/internal/auth"
)

func mintToken(agent string) string {
	if agent == "" {
		agent = "support-agent"
	}
	t, err := auth.IssueDevToken(*jwtSecret, agent, "bench", 1*time.Hour)
	if err != nil {
		fatal(err)
	}
	return t
}
