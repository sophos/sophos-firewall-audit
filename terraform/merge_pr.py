import os
import json
from github import Github

password = os.environ['GH_TOKEN']
merge_into_branch = "main"

gh = Github(password)
gh_repo = gh.get_organization("sophos-internal").get_repo("it.netauto.firewall-audit-results")

pr_body = f"New results added by Factory Firewall Audit pipeline"

pr = gh_repo.create_pull(
  title=f"Updated Results",
  body=pr_body,
  head=f"factory-pipeline-results",
  base=merge_into_branch,
)
print(json.dumps({"PR Created": str(pr.number)}))

result = pr.merge()
print(f"PR Merge result: {result}")

ref = gh_repo.get_git_ref(f"heads/factory-pipeline-results")
ref.delete()
print(f"Deleted branch factory-pipeline-result")