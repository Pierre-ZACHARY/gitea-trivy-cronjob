This repo contains a Go script that should run in a trivy container to scan all repos of your gitea instance which the user has access.

You should still run trivy as part of your CI before pushing a new image into your registry, but this bot allows for regular scans of all repos in case a new vulnerability is detected, just like a renovate bot.

You should create a new user for the bot and an access token on its account.

It will automatically create and manage issues based on trivy reports.

Env variables : 
- DRY_RUN : true/false ( if you only want to test the bot and not actually create any issues )
- ENTRYPOINT_URL : https://<yourgiteainstance>.com/
- GITEA_TOKEN : your gitea user access token with read:package write:issue permissions

TODOS :
- currently only runs on a single pod at a time ( will always scan all repos ), which might take a long time depending on the number of repos to scan. Distributing the scans into a daemonset of pods could be nice to have 
- set a caching system with a persistent volume to avoid re-downloading trivy DB and each individual repos at every new run

quick start : 
>kubectl apply -n <your-namespace> cronjob.yaml
