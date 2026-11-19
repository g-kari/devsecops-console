package ghcommand

import (
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var repositoryName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
var ownerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
var releaseTag = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

func qualifiedRepo(repo string) (string, error) {
	parts := strings.Split(repo, "/")
	if len(parts) != 2 || !ownerName.MatchString(parts[0]) || !repositoryName.MatchString(parts[1]) || parts[1] == "." || parts[1] == ".." {
		return "", errors.New("explicit GitHub owner/repository is required")
	}
	return "github.com/" + repo, nil
}

// pinGitHub deliberately accepts only the application's existing command shapes.
// In particular, a PR URL, -R, --repo=, arbitrary endpoint or hostname cannot
// redirect an operation away from the host whose identity was checked.
func pinGitHub(args []string) ([]string, error) {
	if len(args) < 2 {
		return nil, ErrCommand
	}
	result := append([]string(nil), args...)
	start := 2
	var allowed map[string]bool
	requireRepo := false
	switch args[0] + " " + args[1] {
	case "api graphql":
		if len(args) != 4 || args[2] != "-f" || !validDependabotUpdatesField(args[3]) {
			return nil, ErrCommand
		}
		return append(result, "--hostname", "github.com"), nil
	case "pr merge":
		if len(args) < 3 {
			return nil, ErrCommand
		}
		n, err := strconv.ParseUint(args[2], 10, 64)
		if err != nil || n == 0 {
			return nil, ErrCommand
		}
		start = 3
		allowed = map[string]bool{"--repo": true, "--squash": false, "--delete-branch": false, "--auto": false}
		requireRepo = true
	case "pr list":
		allowed = map[string]bool{"--repo": true, "--author": true, "--state": true, "--json": true, "--limit": true}
		requireRepo = true
	case "repo view":
		if len(args) < 3 {
			return nil, ErrCommand
		}
		repo, err := qualifiedRepo(args[2])
		if err != nil {
			return nil, err
		}
		result[2] = repo
		start = 3
		allowed = map[string]bool{"--json": true, "--jq": true}
	case "repo list":
		if len(args) < 3 || !ownerName.MatchString(args[2]) {
			return nil, ErrCommand
		}
		start = 3
		allowed = map[string]bool{"--json": true, "--jq": true, "--limit": true}
	case "release download":
		if len(args) < 3 || !releaseTag.MatchString(args[2]) {
			return nil, ErrCommand
		}
		start = 3
		allowed = map[string]bool{"--repo": true, "--pattern": true, "--dir": true}
		requireRepo = true
	default:
		if args[0] != "api" || !allowedEndpoint(args[1]) {
			return nil, ErrCommand
		}
		allowed = map[string]bool{"--paginate": false, "--jq": true}
	}
	seen := map[string]int{}
	for i := start; i < len(result); i++ {
		flag := result[i]
		hasValue, ok := allowed[flag]
		if !ok {
			return nil, ErrCommand
		}
		seen[flag]++
		if seen[flag] > 1 && flag != "--pattern" {
			return nil, ErrCommand
		}
		if !hasValue {
			continue
		}
		i++
		if i >= len(result) {
			return nil, ErrCommand
		}
		value := result[i]
		switch flag {
		case "--repo":
			repo, err := qualifiedRepo(value)
			if err != nil {
				return nil, err
			}
			result[i] = repo
		case "--author":
			if value != "app/dependabot" {
				return nil, ErrCommand
			}
		case "--state":
			if value != "open" {
				return nil, ErrCommand
			}
		case "--limit":
			if value != "100" && value != "1000" {
				return nil, ErrCommand
			}
		case "--json":
			switch value {
			case "homepageUrl", "defaultBranchRef", "isArchived", "name,isArchived,pushedAt,defaultBranchRef,homepageUrl", "name", "number,title":
			default:
				return nil, ErrCommand
			}
		case "--jq":
			switch value {
			case ".homepageUrl", ".defaultBranchRef.name", ".isArchived", ".[].name", "length", "[.rate.remaining, .rate.reset] | @tsv":
			default:
				return nil, ErrCommand
			}
		case "--pattern":
			if value == "" || strings.ContainsAny(value, "/\\\x00\r\n") || value == "." || value == ".." {
				return nil, ErrCommand
			}
		case "--dir":
			if value == "" || strings.ContainsRune(value, 0) {
				return nil, ErrCommand
			}
		}
	}
	if requireRepo && seen["--repo"] != 1 {
		return nil, ErrCommand
	}
	if args[0] == "api" {
		result = append(result, "--hostname", "github.com")
	}
	return result, nil
}

func allowedEndpoint(endpoint string) bool {
	if strings.ContainsAny(endpoint, "\\\x00\r\n#%") || strings.HasPrefix(endpoint, "//") {
		return false
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	valid := false
	if len(parts) == 1 {
		valid = parts[0] == "rate_limit" || parts[0] == "user"
	}
	if len(parts) >= 4 && parts[0] == "repos" {
		if _, err := qualifiedRepo(parts[1] + "/" + parts[2]); err != nil {
			return false
		}
		tail := strings.Join(parts[3:], "/")
		valid = tail == "contributors" || tail == "dependabot/alerts" || tail == "releases/latest"
	}
	if len(parts) == 4 && parts[0] == "orgs" && ownerName.MatchString(parts[1]) {
		valid = parts[2] == "dependabot" && parts[3] == "alerts"
	}
	if !valid {
		return false
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return false
	}
	for key, values := range query {
		if len(values) != 1 {
			return false
		}
		switch key {
		case "state":
			if values[0] != "open" {
				return false
			}
		case "per_page":
			if values[0] != "100" {
				return false
			}
		case "severity":
			for _, value := range strings.Split(values[0], ",") {
				if value != "critical" && value != "high" && value != "medium" && value != "low" {
					return false
				}
			}
		default:
			return false
		}
	}
	return true
}
