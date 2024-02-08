package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
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
	PrimaryURL    string        `json:"primary_url"`
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

func processTrivyResult(owner string, repoName string, branch string, resultPath string, commitId string) error {
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
		for _, misconf := range target.Misconfigurations {
			description += "\n|" + misconf.ID + "<br/>" + misconf.Type
			description += "|" + misconf.Title
			info := misconf.Description + "<br/><br/><u>Resolution:</u> " + misconf.Resolution
			if misconf.CauseMetadata.Code != nil && misconf.CauseMetadata.Code.Lines != nil {
				for _, line := range misconf.CauseMetadata.Code.Lines {
					if line.FirstCause {
						lineNumberStr := strconv.Itoa(line.Number)
						info += "<br/><br/><a href='" + entryPointURL + "/" + owner + "/" + repoName + "/src/commit/" + commitId + "/" + target.Target + "#L" + lineNumberStr + "'>Line " + lineNumberStr + "</a>:"
					}
					info += "<br/>" + linePrefix(line.FirstCause, line.LastCause) + "<span>" + line.Content + "</span>"
				}
			}
			description += "|" + Colorize(misconf.Severity)
			description += "|" + info
			description += "|"
		}

		err = createIssue(owner, repoName, target.Target+" @"+branch, description, dryRun, authToken, entryPointURL)
		if err != nil {
			return err
		}
	}
	return nil
}
