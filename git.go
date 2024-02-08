package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func gitCloneOrUpdateUnderCurrentRepository(repoURL string, dirName string) {
	path := fmt.Sprintf("%s/%s", ".", dirName)

	// Check if Git executable is available
	_, err := exec.LookPath("git")
	if err != nil {
		log.Fatalf("Git executable not found: %v\n", err)
	}

	// Check if target directory exists
	info, err := os.Stat(path)
	if !os.IsNotExist(err) && info.IsDir() {
		// Directory exists, so we will pull the latest changes
		cmd := exec.Command("git", "-C", path, "pull")
		var out bytes.Buffer
		cmd.Stdout = &out
		err = cmd.Run()
		if err != nil {
			log.Printf("Error while pulling updates: %v\n%s", err, out.String())
		}
	} else {
		// Directory does not exist, so we will clone the repository
		cmd := exec.Command("git", "clone", repoURL, dirName)
		var out bytes.Buffer
		cmd.Stdout = &out
		err = cmd.Run()
		if err != nil {
			log.Printf("Error while cloning repository: %v\n%s", err, out.String())
		}
	}
}

type TrivyConfig struct {
	Branches []string `json:"branches"`
	Severity string   `json:"severity"`
}

func contains(slice []string, item string) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}

func checkoutBranch(branchName string) error {
	cmd := exec.Command("git", "checkout", branchName)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to checkout branch %s: \n%w\n%s", branchName, err, output)
	}

	return nil
}

func currentCommitHash() (string, error) {
	cmd := exec.Command("git", "rev-parse", "HEAD")

	hashBytes, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("unable to retrieve current commit hash: %w", err)
	}

	currentHash := strings.TrimSpace(string(hashBytes))
	return currentHash, nil
}
