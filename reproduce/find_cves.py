import github3
import re
import xml.etree.ElementTree as ET

def extract_reproduce_issues(description, cve):
    """
    :param description like CONFIRM:https://github.com/libarchive/libarchive/issues/711
    :param cve: cve_id
    :return:  (owner,repo), (cve, issue)
    """
    splitted = description.split("/")
    return (splitted[3],splitted[4]), (cve, splitted[-1])

def parse_vulnerability_tag(vulnerability):
    """
    parsing one vulnerability tag
    """
    cve_id = list(vulnerability.iter("{http://www.icasi.org/CVRF/schema/vuln/1.1}CVE"))[0].text
    descriptions = vulnerability.iter('{http://www.icasi.org/CVRF/schema/vuln/1.1}Description')
    is_github_issue = lambda x: "confirm:" in x and "//github" in x and "issues" in x
    wanted_descriptions = filter(is_github_issue, map(lambda x: x.text.lower(), descriptions))
    if len(wanted_descriptions) > 0:
        return extract_reproduce_issues(wanted_descriptions[0], cve_id)
    return None, None

def parse_cve_xml(cve_path):
    """
    returns dict of (github repo -> (cve, issue))
    :param cve_path:
    :return:
    """
    tree = ET.parse(cve_path)
    root = tree.getroot()
    repos_vuls = {}
    for child in root.iter('{http://www.icasi.org/CVRF/schema/vuln/1.1}Vulnerability'):
            key, value = parse_vulnerability_tag(child)
            if key is not None:
                repos_vuls.setdefault(key, []).append(value)
    return repos_vuls


def extract_links(html):
    to_remove = ["</a>","</a>.","</li>","</p>","</span>","<span>","<span", "<br>"]
    new_html = html
    for elem in to_remove:
        new_html = new_html.replace(elem, "")
    return re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', new_html)

def filter_body_links(link):
    """
    filter link to aviod non files links
    """
    not_commit = not ("github" in link and "commit" in link)
    not_pull = not ("github" in link and "pull" in link)
    not_tag = not ("github" in link and "tag" in link)
    not_issue = not ("github" in link and "issues" in link)
    not_release = not ("github" in link and "releases" in link)
    not_php = not (".php" in link)
    not_openwall = not ("openwall.com" in link)
    not_stackoverflow = not ("stackoverflow.com" in link)
    not_bugs_launchpad = not ("bugs.launchpad.net" in link)
    not_google = not ("code.google" in link)
    not_pubs_opengroup = not ("pubs.opengroup" in link)
    not_bugs_debian = not (".debian" in link)
    return not_commit and not_pull and not_tag and not_release and not_issue and \
           not_php and not_openwall and not_stackoverflow and not_bugs_launchpad and not_google \
           and not_pubs_opengroup and not_bugs_debian

def get_issue_properties(repo, issue_id):
    issue = repo.issue(issue_id)
    if not issue.is_closed():
        return [], []
    body_links = filter(filter_body_links, extract_links(issue.body_html))
    commits_links = filter(lambda x: "commit" in x or True, map(lambda c: extract_links(c.body_html), issue.iter_comments()))
    # fix_commit = ""
    # if len(commits_links) > 0:
    #     fix_commit = commits_links[-1].split("/")[-1]
    return body_links, commits_links


def get_repos_data(repos_issues):
    gh = github3.GitHub("amir9979@gmail.com", "192837465a")
    detailed_issues = {}
    for owner, repo in repos_issues:
        repository = gh.repository(owner, repo)
        if repository is None or repository.language is None or repository.language.lower() not in ["c", "cpp", "c++"]:
            continue
        for cve, issue in repos_issues[(owner, repo)]:
            try:
                body_links, fix_commit = get_issue_properties(repository, issue)
                if body_links != [] :
                    print body_links, fix_commit
            except:
                pass

if __name__ == "__main__":
    d = parse_cve_xml(r"C:\Users\User\Downloads\allitems-cvrf.xml")
    get_repos_data(d)
    print d.keys()
