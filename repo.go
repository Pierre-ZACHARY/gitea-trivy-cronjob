package main

type RepositoryExternalTracker struct {
	ExternalTrackerFormat        string `json:"external_tracker_format"`
	ExternalTrackerRegexpPattern string `json:"external_tracker_regexp_pattern"`
	ExternalTrackerStyle         string `json:"external_tracker_style"`
	ExternalTrackerURL           string `json:"external_tracker_url"`
}

type RepositoryExternalWiki struct {
	ExternalWikiURL string `json:"external_wiki_url"`
}

type InternalTracker struct {
	AllowOnlyContributorsToTrackTime bool `json:"allow_only_contributors_to_track_time"`
	EnableIssueDependencies          bool `json:"enable_issue_dependencies"`
	EnableTimeTracker                bool `json:"enable_time_tracker"`
}

type Organization struct {
	AvatarURL                 string `json:"avatar_url"`
	Description               string `json:"description"`
	Email                     string `json:"email"`
	FullName                  string `json:"full_name"`
	Id                        int    `json:"id"`
	Location                  string `json:"location"`
	Name                      string `json:"name"`
	RepoAdminChangeTeamAccess bool   `json:"repo_admin_change_team_access"`
	Username                  string `json:"username"`
	Visibility                string `json:"visibility"`
	Website                   string `json:"website"`
}

type Team struct {
	CanCreateOrgRepo        bool              `json:"can_create_org_repo"`
	Description             string            `json:"description"`
	Id                      int               `json:"id"`
	IncludesAllRepositories bool              `json:"includes_all_repositories"`
	Name                    string            `json:"name"`
	Organization            Organization      `json:"organization"`
	Permission              string            `json:"permission"`
	Units                   []string          `json:"units"`
	UnitsMap                map[string]string `json:"units_map"`
}

type Unit struct {
	Active            bool   `json:"active"`
	AvatarURL         string `json:"avatar_url"`
	Created           string `json:"created"`
	Description       string `json:"description"`
	Email             string `json:"email"`
	FollowersCount    int    `json:"followers_count"`
	FollowingCount    int    `json:"following_count"`
	FullName          string `json:"full_name"`
	Id                int    `json:"id"`
	IsAdmin           bool   `json:"is_admin"`
	Language          string `json:"language"`
	LastLogin         string `json:"last_login"`
	Location          string `json:"location"`
	Login             string `json:"login"`
	LoginName         string `json:"login_name"`
	ProhibitLogin     bool   `json:"prohibit_login"`
	Restricted        bool   `json:"restricted"`
	StarredReposCount int    `json:"starred_repos_count"`
	Visibility        string `json:"visibility"`
	Website           string `json:"website"`
}

type RepositoryOwner struct {
	Active            bool   `json:"active"`
	AvatarURL         string `json:"avatar_url"`
	Created           string `json:"created"`
	Description       string `json:"description"`
	Email             string `json:"email"`
	FollowersCount    int    `json:"followers_count"`
	FollowingCount    int    `json:"following_count"`
	FullName          string `json:"full_name"`
	Id                int    `json:"id"`
	IsAdmin           bool   `json:"is_admin"`
	Language          string `json:"language"`
	LastLogin         string `json:"last_login"`
	Location          string `json:"location"`
	Login             string `json:"login"`
	LoginName         string `json:"login_name"`
	ProhibitLogin     bool   `json:"prohibit_login"`
	Restricted        bool   `json:"restricted"`
	StarredReposCount int    `json:"starred_repos_count"`
	Visibility        string `json:"visibility"`
	Website           string `json:"website"`
}

type RepositoryPermissions struct {
	Admin bool `json:"admin"`
	Pull  bool `json:"pull"`
	Push  bool `json:"push"`
}

type Repository struct {
	AllowMergeCommits             bool                      `json:"allow_merge_commits"`
	AllowRebase                   bool                      `json:"allow_rebase"`
	AllowRebaseExplicit           bool                      `json:"allow_rebase_explicit"`
	AllowRebaseUpdate             bool                      `json:"allow_rebase_update"`
	AllowSquashMerge              bool                      `json:"allow_squash_merge"`
	Archived                      bool                      `json:"archived"`
	ArchivedAt                    TimeString                `json:"archived_at"`
	AvatarURL                     string                    `json:"avatar_url"`
	CloneURL                      string                    `json:"clone_url"`
	CreatedAt                     TimeString                `json:"created_at"`
	DefaultAllowMaintainerEdit    bool                      `json:"default_allow_maintainer_edit"`
	DefaultBranch                 string                    `json:"default_branch"`
	DefaultDeleteBranchAfterMerge bool                      `json:"default_delete_branch_after_merge"`
	DefaultMergeStyle             string                    `json:"default_merge_style"`
	Description                   string                    `json:"description"`
	Empty                         bool                      `json:"empty"`
	ExternalTracker               RepositoryExternalTracker `json:"external_tracker"`
	ExternalWiki                  RepositoryExternalWiki    `json:"external_wiki"`
	Fork                          bool                      `json:"fork"`
	ForksCount                    int                       `json:"forks_count"`
	FullName                      string                    `json:"full_name"`
	HasActions                    bool                      `json:"has_actions"`
	HasIssues                     bool                      `json:"has_issues"`
	HasPackages                   bool                      `json:"has_packages"`
	HasProjects                   bool                      `json:"has_projects"`
	HasPullRequests               bool                      `json:"has_pull_requests"`
	HasReleases                   bool                      `json:"has_releases"`
	HasWiki                       bool                      `json:"has_wiki"`
	HTMLURL                       string                    `json:"html_url"`
	ID                            int                       `json:"id"`
	IgnoreWhitespaceConflicts     bool                      `json:"ignore_whitespace_conflicts"`
	Internal                      bool                      `json:"internal"`
	InternalTracker               InternalTracker           `json:"internal_tracker"`
	Language                      string                    `json:"language"`
	LanguagesURL                  string                    `json:"languages_url"`
	Link                          string                    `json:"link"`
	Mirror                        bool                      `json:"mirror"`
	MirrorInterval                string                    `json:"mirror_interval"`
	MirrorUpdated                 TimeString                `json:"mirror_updated"`
	Name                          string                    `json:"name"`
	OpenIssuesCount               int                       `json:"open_issues_count"`
	OpenPRCounter                 int                       `json:"open_pr_counter"`
	OriginalURL                   string                    `json:"original_url"`
	Owner                         RepositoryOwner           `json:"owner"`
	Parent                        string                    `json:"parent"`
	Permissions                   RepositoryPermissions     `json:"permissions"`
	Private                       bool                      `json:"private"`
	ReleaseCounter                int                       `json:"release_counter"`
	Size                          int                       `json:"size"`
	SSHURL                        string                    `json:"ssh_url"`
	StarsCount                    int                       `json:"stars_count"`
	Template                      bool                      `json:"template"`
	UpdatedAt                     TimeString                `json:"updated_at"`
	URL                           string                    `json:"url"`
	WatchersCount                 int                       `json:"watchers_count"`
	Website                       string                    `json:"website"`
}

type TimeString string
