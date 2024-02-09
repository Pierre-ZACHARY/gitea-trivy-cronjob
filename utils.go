package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
)

type SeverityColorizer interface {
	Colorize(severity string) string
}

func Colorize(severity string) string {
	switch severity {
	case "CRITICAL":
		return "<span style='color: red'>" + severity + "</span>"
	case "HIGH":
		return "<span style='color: orange'>" + severity + "</span>"
	case "MEDIUM":
		return "<span style='color: yellow+'>" + severity + "</span>"
	default:
		return "<span>" + severity + "</span>"
	}
}

func escapeSpecialChars(input string) string {
	// Escape quotes
	escapedQuotes := regexp.MustCompile(`"`).ReplaceAllStringFunc(input, func(match string) string {
		return "\\" + match
	})

	// Escape backslashes
	escapedBackslashes := regexp.MustCompile(`\\`).ReplaceAllStringFunc(escapedQuotes, func(match string) string {
		return "\\" + match
	})
	return escapedBackslashes
}

func createIssue(owner, repo, title, desc string, dryRun bool, giteaToken string, giteaEndpoint string) error {
	jsonBody := fmt.Sprintf(`{"title":"%s","body":"%s"}`, title, escapeSpecialChars(desc))
	bodyBytes := []byte(jsonBody)

	postEndpoint := fmt.Sprintf("%s/api/v1/repos/%s/%s/issues", trimTrailingSlashIfExists(entryPointURL), owner, repo)
	request, err := http.NewRequest("POST", postEndpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return err
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Authorization", "token "+giteaToken)

	if dryRun {
		fmt.Printf("DRY_RUN enabled: Would have made a POST request to %s with body %s.\n", postEndpoint, jsonBody)
	} else {
		fmt.Printf("POST request to %s with body %s.\n", postEndpoint, jsonBody)
		client := &http.Client{}
		response, err := client.Do(request)
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

func linePrefix(isFirst, isLast bool) string {
	if isFirst && isLast {
		return ">"
	} else if isFirst {
		return "┌"
	} else if isLast {
		return "└"
	} else {
		return "│"
	}
}

func makeAPIRequest(url string) []byte {
	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		log.Fatalf("Error creating http request : %s %s", url, err)
	}

	acceptHeaders := map[string][]string{
		"Accept": {"application/json"},
	}
	for key, values := range acceptHeaders {
		req.Header.Set(key, strings.Join(values, ", "))
	}

	authHeaders := map[string][]string{
		"Authorization": {"token " + authToken},
	}
	for key, values := range authHeaders {
		req.Header.Set(key, strings.Join(values, ", "))
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	check(err)
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	return bodyBytes
}

func navigate(path string) {
	err := os.Chdir(path)
	if err != nil {
		log.Fatal(err)
	}
	wd, _ := os.Getwd()
	fmt.Println("Current Directory : " + wd)
}
