package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

var entryPointURL string
var authToken string
var dryRun bool
var patchedIssues []int

const configFile string = "trivy.json"

func init() {
	dryRun = os.Getenv("DRY_RUN") != "false"
	fmt.Println("DRY_RUN =", dryRun)
	authToken = os.Getenv("GITEA_TOKEN")
	if authToken == "" {
		log.Fatalf("Please set your GITEA_TOKEN env variable. To do that, create a 'TrivyBot' user in your gitea instance; then on that user create an access token with read:repository write:issue permissions.")
	}
	entryPointURL = os.Getenv("ENTRYPOINT_URL")
	if entryPointURL == "" {
		log.Fatalf("Please set your ENTRYPOINT_URL env variable. eg https://yourgiteainstancedomain.com/")
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func trimTrailingSlashIfExists(str string) string {
	if strings.HasSuffix(str, "/") {
		return str[:len(str)-1]
	}
	return str
}

func main() {
	userReposEndpoint := fmt.Sprintf("%s/api/v1/user/repos?topic=false&includeDesc=false&exclusive=false", trimTrailingSlashIfExists(entryPointURL))

	responseData := makeAPIRequest(userReposEndpoint)

	currentUser := getCurrentUser()
	fmt.Println("Current username:", currentUser.Login)

	var repositories []Repository
	err := json.Unmarshal(responseData, &repositories)
	if err != nil {
		log.Fatalf("Error occurred parsing JSON: %v", err)
	}

	currentDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to determine the current working directory: %v", err)
	}

	// Iterate through all repositories and print their owners and names.
	for _, repo := range repositories {

		// check all repo issues from current user ( we might need to re-open them or close them )
		issues := getRepoIssue(repo.Owner.Login, repo.Name, currentUser.Login)
		fmt.Println(issues)
		var branches []string
		severityKey := "HIGH,CRITICAL"

		fmt.Println("Current repo : " + repo.CloneURL)
		gitCloneOrUpdateUnderCurrentRepository(repo.CloneURL, repo.Name)
		navigate(repo.Name)

		cfg, err := validateTrivyJSON(configFile)
		if err == nil {
			fmt.Printf("Trivy.Json config:\nBranches: %v\nSeverity: %s\n", cfg.Branches, cfg.Severity)
			branches = append(branches, cfg.Branches...)
			severityKey = cfg.Severity
		} else if strings.Contains(err.Error(), "open trivy.json") { // no config file
			branches = append(branches, repo.DefaultBranch)
		} else {
			fmt.Println("Validation failed:", err)
			continue
		}

		fmt.Println(severityKey)
		for _, branch := range branches {
			err := checkoutBranch(branch)
			if err != nil {
				fmt.Println("Encountered an error checking out branch:", err)
			}

			currentHash, err := currentCommitHash()
			if err != nil {
				fmt.Println("Encountered an error obtaining current commit hash:", err)
			}

			fmt.Println("commit hash : " + currentHash)

			outputDir := "/output/" + repo.Owner.Login + "/" + repo.Name + "/" + branch
			fmt.Println("Scanner output directory is :", outputDir)
			err = os.MkdirAll(outputDir, os.ModePerm)
			if err != nil {
				fmt.Println("Encountered an error while creating output dir:", err)
			}

			err = runTrivyScanToJson(filepath.Join(outputDir, "fs.json"), ".", "fs", severityKey)
			if err != nil {
				fmt.Println("Encountered an error while running Trivy FS scan:", err)
			}

			err = runTrivyScanToJson(filepath.Join(outputDir, "config.json"), ".", "config", severityKey)
			if err != nil {
				fmt.Println("Encountered an error while running Trivy CONFIG scan:", err)
			}

			err = processTrivyResult(repo.Owner.Login, repo.Name, branch, filepath.Join(outputDir, "fs.json"), currentHash, issues)
			if err != nil {
				fmt.Println("Failed to process fs.json", "branch:"+branch, err)
			}

			err = processTrivyResult(repo.Owner.Login, repo.Name, branch, filepath.Join(outputDir, "config.json"), currentHash, issues)
			if err != nil {
				fmt.Println("Failed to process config.json", "branch:"+branch, err)
			}
		}
		navigate(currentDir)

		// next we need to close all existing issues that weren't patched ( meaning there is no issue anymore )
		for _, issue := range issues {
			if !issue.Locked && issue.State != "closed" {
				if !slices.Contains(patchedIssues, issue.ID) {
					err := patchIssue(repo.Owner.Login, repo.Name, issue.ID, "closed", issue.Body)
					if err != nil {
						fmt.Println("Failed to close an issue :", issue.Title, issue.URL, err)
					}
				}
			}
		}

		// remove the repo directory to gain space
		err = os.RemoveAll(currentDir + "/" + repo.Name)
		if err != nil {
			fmt.Println("Failed to remove repository :", repo.Name)
		}
	}

}
