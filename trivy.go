package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
)

func validateTrivyJSON(filename string) (*TrivyConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg TrivyConfig
	err = json.Unmarshal([]byte(data), &cfg)
	if err != nil {
		return nil, err
	}

	allowedSeverities := strings.Fields("CRITICAL HIGH MEDIUM LOW NEGLIGIBLE UNKNOWN")
	if !contains(allowedSeverities, cfg.Severity) {
		return nil, fmt.Errorf("invalid severity '%s', must be one of %v", cfg.Severity, allowedSeverities)
	}

	for _, branch := range cfg.Branches {
		trimmedBranch := strings.TrimSpace(branch)
		if trimmedBranch == "" {
			continue
		}

		_, err := exec.Command("git", "rev-parse", "--symbolic-full-name", "--abbrev-ref", "--quiet", trimmedBranch).Output()
		if err != nil {
			return nil, fmt.Errorf("branch '%s' does not exist in the local repository", trimmedBranch)
		}
	}

	return &cfg, nil
}

func runTrivyScanToJson(outputPath, pattern string, trivyCommand string, severity string) error {
	args := []string{
		trivyCommand,
		"--format", "json",
		"--output", outputPath,
		"--severity", severity,
		pattern,
	}

	cmd := exec.Command("trivy", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

type CauseMetadata struct {
	Provider  string      `json:"provider"`
	Service   string      `json:"service"`
	StartLine *int        `json:"StartLine,omitempty"`
	EndLine   *int        `json:"EndLine,omitempty"`
	Code      *CodeStruct `json:"code,omitempty"`
}

type CodeStruct struct {
	Lines []struct {
		Number     int
		Content    string
		IsCause    bool
		Annotation string
		Truncated  bool
		FirstCause bool
		LastCause  bool
	} `json:"lines,omitempty"`
}

type SchemaVersion uint

type ArtifactType string

type Status string

type Result struct {
	Target            string          `json:"target"`
	Class             string          `json:"class"`
	Type              string          `json:"type"`
	MisconfSummary    MisconfSum      `json:"MisconfSummary"`
	Misconfigurations []Misconfig     `json:"misconfigurations,omitempty"`
	Vulnerabilities   []Vulnerability `json:"Vulnerabilities,omitempty"`
}

type MisconfSum struct {
	Successes  int `json:"successes"`
	Failures   int `json:"failures"`
	Exceptions int `json:"exceptions"`
}
type Identifier struct {
	PURL string `json:"PURL"`
}

type Vulnerability struct {
	VulnerabilityID  string          `json:"VulnerabilityID"`
	PkgName          string          `json:"PkgName"`
	PkgIdentifier    Identifier      `json:"PkgIdentifier"`
	InstalledVersion string          `json:"InstalledVersion"`
	FixedVersion     string          `json:"FixedVersion"`
	Status           string          `json:"Status"`
	Layer            json.RawMessage `json:"Layer"`
	SeveritySource   string          `json:"SeveritySource"`
	PrimaryURL       string          `json:"PrimaryURL"`
	Title            string          `json:"Title"`
	Description      string          `json:"Description"`
	Severity         string          `json:"Severity"`
	CweIDs           []string        `json:"CweIDs"`
	References       []string        `json:"References"`
	PublishedDate    string          `json:"PublishedDate"`
	LastModifiedDate string          `json:"LastModifiedDate"`
}

type Misconfig struct {
	Type          string        `json:"type"`
	ID            string        `json:"id"`
	AVDID         string        `json:"avdid"`
	Title         string        `json:"title"`
	Description   string        `json:"description"`
	Message       string        `json:"message"`
	Namespace     string        `json:"namespace"`
	Query         string        `json:"query"`
	Resolution    string        `json:"resolution"`
	Severity      string        `json:"severity"`
	PrimaryURL    string        `json:"PrimaryURL"`
	References    []string      `json:"references"`
	Status        Status        `json:"status"`
	CauseMetadata CauseMetadata `json:"CauseMetadata"`
}

type ScanResult struct {
	SchemaVersion SchemaVersion `json:"schema_version"`
	CreatedAt     string        `json:"created_at"`
	ArtifactName  string        `json:"artifact_name"`
	ArtifactType  ArtifactType  `json:"artifact_type"`
	Results       []Result      `json:"results"`
}

func processTrivyResult(owner string, repoName string, branch string, resultPath string, commitId string, repoIssues []Issue) error {
	data, err := os.ReadFile(resultPath)
	if err != nil {
		return err
	}

	var result ScanResult
	err = json.Unmarshal([]byte(data), &result)
	if err != nil {
		return err
	}
	if dryRun {
		fmt.Println("DRY_RUN :", resultPath, result)
	}
	for _, target := range result.Results {
		// each target is a file; it will result in a new issue
		description := target.Class
		description += "\n| Type | Title | Severity | Info |"
		description += "\n| --- | --- | --- | --- |"
		for _, vulne := range target.Vulnerabilities {
			description += "\n|<a href='" + vulne.PrimaryURL + "'>" + vulne.VulnerabilityID + "<br/>" + vulne.PkgName + "</a>"
			description += "|" + vulne.Title
			description += "|" + Colorize(vulne.Severity)
			info := strings.ReplaceAll(vulne.Description, "\n", "<br/>")
			info += "<br/>Published at: " + vulne.PublishedDate
			info += "<br/><br/>Installed Version: " + vulne.InstalledVersion + " --> <u>Fixed version: " + vulne.FixedVersion + "</u>"
			description += "|" + info
			description += "|"
		}

		for _, misconf := range target.Misconfigurations {
			description += "\n|<a href='" + misconf.PrimaryURL + "'>" + misconf.ID + "<br/>" + misconf.Type + "</a>"
			description += "|" + misconf.Title
			description += "|" + Colorize(misconf.Severity)
			info := strings.ReplaceAll(misconf.Description, "\n", "<br/>") + "<br/><br/><u>Resolution:</u> " + strings.ReplaceAll(misconf.Resolution, "\n", "<br/>")
			if misconf.CauseMetadata.Code != nil && misconf.CauseMetadata.Code.Lines != nil {
				for _, line := range misconf.CauseMetadata.Code.Lines {
					if line.FirstCause {
						lineNumberStr := strconv.Itoa(line.Number)
						info += "<br/><br/><a href='" + entryPointURL + "/" + owner + "/" + repoName + "/src/commit/" + commitId + "/" + target.Target + "#L" + lineNumberStr + "'>Line " + lineNumberStr + "</a>:"
					}
					info += "<br/>" + linePrefix(line.FirstCause, line.LastCause) + "<span>" + line.Content + "</span>"
				}
			}
			description += "|" + info
			description += "|"
		}

		newIssueTitle := target.Target + " @" + branch
		// check if an issue with the same name exist, in this case we only patch it
		issueDoExist := false
		for _, issue := range repoIssues {
			if issue.Title == newIssueTitle {
				if issue.Locked {
					fmt.Printf("WARN: Issue with the name %s do exist but is locked, can't patch it, skipping\n", newIssueTitle)
					continue
				}
				issueDoExist = true
				patchedIssues = append(patchedIssues, issue.ID)
				// don't send the request if the description is the same
				if issue.Body != description || issue.State == "closed" {
					err = patchIssue(owner, repoName, issue.ID, "open", description)
					if err != nil {
						return err
					}
				} else {
					fmt.Printf("INFO: Same name and description, skipping the patch request for issue '%s'\n", newIssueTitle)
				}
				break
			}
		}
		if !issueDoExist {
			err = createIssue(owner, repoName, newIssueTitle, description, dryRun, authToken, entryPointURL)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

type User struct {
	Id    int64  `json:"id"`
	Login string `json:"login"`
}

func getCurrentUser() User {
	userReposEndpoint := fmt.Sprintf("%s/api/v1/user/", trimTrailingSlashIfExists(entryPointURL))

	responseData := makeAPIRequest(userReposEndpoint)

	var user User
	err := json.Unmarshal(responseData, &user)
	if err != nil {
		log.Fatalf("Error occurred parsing JSON: %v", err)
	}

	return user
}

type IssueUser struct {
	ID                int    `json:"id"`
	Login             string `json:"login"`
	LoginName         string `json:"login_name"`
	FullName          string `json:"full_name"`
	Email             string `json:"email"`
	AvatarURL         string `json:"avatar_url"`
	Language          string `json:"language"`
	IsAdmin           bool   `json:"is_admin"`
	LastLogin         string `json:"last_login"`
	Created           string `json:"created"`
	Restricted        bool   `json:"restricted"`
	Active            bool   `json:"active"`
	ProhibitLogin     bool   `json:"prohibit_login"`
	Location          string `json:"location"`
	Website           string `json:"website"`
	Description       string `json:"description"`
	Visibility        string `json:"visibility"`
	FollowersCount    int    `json:"followers_count"`
	FollowingCount    int    `json:"following_count"`
	StarredReposCount int    `json:"starred_repos_count"`
	Username          string `json:"username"`
}

type IssueAsset struct {
	Name        string `json:"name"`
	Size        int    `json:"size"`
	DownloadURL string `json:"download_url"`
	ContentType string `json:"content_type"`
	State       string `json:"state"`
}

type IssueLabel struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Color   string `json:"color"`
	Desc    string `json:"desc"`
	Default bool   `json:"default"`
}

type IssueMilestone struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
}

type Issue struct {
	ID               int             `json:"id"`
	URL              string          `json:"url"`
	HTMLURL          string          `json:"html_url"`
	Number           int             `json:"number"`
	User             IssueUser       `json:"user"`
	OriginalAuthor   string          `json:"original_author"`
	OriginalAuthorID int             `json:"original_author_id"`
	Title            string          `json:"title"`
	Body             string          `json:"body"`
	Ref              string          `json:"ref"`
	Assets           []IssueAsset    `json:"assets"`
	Labels           []IssueLabel    `json:"labels"`
	Milestone        *IssueMilestone `json:"milestone"`
	Assignee         string          `json:"assignee"`
	Assignees        []string        `json:"assignees"`
	State            string          `json:"state"`
	Locked           bool            `json:"is_locked"`
	Comments         int             `json:"comments"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
	ClosedAt         *time.Time      `json:"closed_at"`
	DueDate          *time.Time      `json:"due_date"`
	PullRequest      *int            `json:"pull_request"`
	Repository       IssuesRepo      `json:"repository"`
	PinOrder         int             `json:"pin_order"`
}

type IssuesRepo struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Owner    string `json:"owner"`
	FullName string `json:"full_name"`
}

func getRepoIssue(owner string, repo string, createdBy string) []Issue {
	repoIssues := fmt.Sprintf("%s/api/v1/repos/%s/%s/issues?state=all&created_by=%s", trimTrailingSlashIfExists(entryPointURL), owner, repo, createdBy)

	responseData := makeAPIRequest(repoIssues)

	var issues []Issue
	err := json.Unmarshal(responseData, &issues)
	if err != nil {
		log.Fatalf("Error occurred parsing JSON: %v", err)
	}

	// sort by most recent
	sort.Slice(issues, func(i, j int) bool {
		return issues[i].CreatedAt.After(issues[j].CreatedAt)
	})

	return issues
}

func patchIssue(owner string, repo string, issueId int, state string, body string) error {
	issueUrl := fmt.Sprintf("%s/api/v1/repos/%s/%s/issues/%s", trimTrailingSlashIfExists(entryPointURL), owner, repo, strconv.Itoa(issueId))

	jsonBody := fmt.Sprintf(`{"state":"%s","body":"%s"}`, state, escapeSpecialChars(body))
	bodyBytes := []byte(jsonBody)

	req, err := http.NewRequest("PATCH", issueUrl, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "token "+authToken)
	if dryRun {
		fmt.Printf("DRY_RUN enabled: Would have made a PATCH request to %s with body %s.\n", issueUrl, jsonBody)
	} else {
		fmt.Printf("PATCH request to %s with body %s.\n", issueUrl, jsonBody)
		client := &http.Client{}
		response, err := client.Do(req)
		if err != nil {
			fmt.Println("Error sending create issue request : ", err)
			return err
		}
		fmt.Println("received status code : ", response.StatusCode)
		if response.StatusCode != 201 {
			fmt.Println("Got an unexpected response : ", response)
		}
		defer response.Body.Close()
	}
	return nil
}
