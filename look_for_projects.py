import csv

CVE_FILE = r"C:\Users\User\Downloads\allitems (2).csv"

def get_github_links(cve_reports):
    reports = map(lambda report: report.replace("CONFIRM:","").replace("URL:","").replace("MISC:","").replace("https:","").replace("http:",""), cve_reports)
    github = map(lambda report: "".join(filter(lambda x: "//github.com" in x, report.split(","))), reports)
    github = map(lambda report: "".join(filter(lambda x: "//github.com" in x, report.split("|"))), github)
    return github

def github_to_projects(github_links):
    github_projects = {}
    for link in github_links:
        project = "/".join(link.replace("//github.com", "").split("/")[:3])
        github_projects.setdefault(project.replace(" ","").replace('"',""), []).append(link)
    return github_projects

def sort_by_size(github_projects):
    project = map(lambda key: (key, len(github_projects[key]), " ".join(github_projects[key])), github_projects)
    return sorted(project, key=lambda item: item[1], reverse=True)

with open(CVE_FILE) as cve:
    vulnerabilities = list(cve.readlines())[12:]
    github = filter(lambda x: "//github.com" in x, vulnerabilities)
    github_links = get_github_links(github)
    github_projects = github_to_projects(github_links)
    sorted_size = sort_by_size(github_projects)
    with open(r"C:\Temp\cve_projects.csv", "wb") as f:
        writer = csv.writer(f).writerows(sorted_size)
    links = []
