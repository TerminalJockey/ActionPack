package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/google/go-github/v53/github"
	"golang.org/x/oauth2"
)

var (
	org       string
	user      string
	pat       string
	sensitive []string = []string{
		"github.event.issue.title",
		"github.event.issue.body",
		"github.event.pull_request.title",
		"github.event.pull_request.body",
		"github.event.comment.body",
		"github.event.review.body",
		"github.event.head_commit.message",
		"github.event.head_commit.author.email",
		"github.event.head_commit.author.name",
		"github.event.pull_request.head.ref",
		"github.event.pull_request.head.label",
		"github.event.pull_request.head.repo.default_branch",
		"github.head_ref",
	}
)

func init() {
	flag.StringVar(&org, "org", "", "organization to scan")
	flag.StringVar(&user, "user", "", "user to scan")
	flag.StringVar(&pat, "pat", "", "personal access token")
	flag.Parse()
}

func main() {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: pat},
	)
	tc := oauth2.NewClient(context.Background(), ts)

	c := github.NewClient(tc)
	var repos []string
	if user == "" && org != "" {
		repos = GetReposByOrg(c, org)
		for x := range repos {
			GetWorkflowData(c, org, repos[x])
		}
	} else if user != "" && org == "" {
		repos = GetReposByUser(c, user)
		for x := range repos {
			GetWorkflowData(c, user, repos[x])
		}
	}

	// repos := GetReposByOrg(c, org)

	// GetWorkflowData(c, "Hashicorp", "Consul")

}

func GetReposByUser(c *github.Client, user string) (repos []string) {
	var allrepos []*github.Repository

	for {
		iterRepo, resp, err := c.Repositories.List(context.Background(), user, nil)
		if err != nil {
			log.Println(err)
		}
		allrepos = append(allrepos, iterRepo...)
		if resp.NextPage == 0 {
			break
		}
	}

	var repoNames []string
	for x := 0; x < len(allrepos); x++ {
		repoNames = append(repoNames, allrepos[x].GetName())
	}
	return repoNames
}

func GetReposByOrg(c *github.Client, org string) (repos []string) {
	var allrepos []*github.Repository
	opt := &github.RepositoryListByOrgOptions{
		ListOptions: github.ListOptions{PerPage: 10},
	}
	for {
		iterRepo, resp, err := c.Repositories.ListByOrg(context.Background(), org, opt)
		if err != nil {
			log.Println(err)
		}
		allrepos = append(allrepos, iterRepo...)
		if resp.NextPage == 0 {
			break
		}
		opt.Page = resp.NextPage
	}

	var repoNames []string
	for x := 0; x < len(allrepos); x++ {
		repoNames = append(repoNames, allrepos[x].GetName())
	}
	return repoNames
}

func GetWorkflowData(c *github.Client, org string, repo string) {

	workflows, _, err := c.Actions.ListWorkflows(context.Background(), org, repo, nil)
	if err != nil {
		log.Println(err)
		return
	}
	for x := 0; x < len(workflows.Workflows); x++ {
		url := strings.Replace(workflows.Workflows[x].GetHTMLURL(), "blob", "raw", 1)
		r, err := http.Get(url)
		if err != nil {
			log.Println(err)
			continue
		}
		bod, err := ioutil.ReadAll(r.Body)
		if err != nil {
			log.Println(err)
		}
		ParseWorkflow(url, string(bod))
	}
}

func ParseWorkflow(url, workflow string) {
	if strings.Contains(workflow, "<title>Page not found") {
		return
	}
	var possibleVuln bool = false
	for x := range sensitive {
		if strings.Contains(workflow, sensitive[x]) {
			possibleVuln = true
		}
	}
	if possibleVuln {
		fmt.Printf("%s may be vulnerable\n", url)
	}
}
