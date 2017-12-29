import csv
import os
import httplib2
from BeautifulSoup import BeautifulSoup, SoupStrainer

CVE_FILE = r"C:\Users\User\Downloads\allitems (5).csv"
WIRESHARK_ATTACHMENTS = r"C:\vulnerabilities\wireshark_reproduce\attachments"
OUT_FILE = r"C:\temp\wireshark.csv"

def clean(report):
    return report.replace("CONFIRM:", "").replace("URL:", "").replace("MISC:", "").replace("https:", "").replace( "http:", "").lower()

def review_to_commit(url):
    def get_commit(url):
        if ";h=" in url:
            return [url.split(";h=")[1]]
        if "commit:" in url:
            return [url.split("commit:")[1]]
        return [url]
    if ";h=" in url or "commit:" in url:
        return get_commit(url)
    http = httplib2.Http(timeout=2000)
    status, response = http.request(url)
    links = map(lambda link: link['href'],
                filter(lambda link: link.has_key('href'), BeautifulSoup(response, parseOnlyThese=SoupStrainer('a'))))
    return list(set(map(get_commit, filter(lambda link: "code.wireshark.org/review/gitweb" in link, links))))


def bug_to_commit(url):
    http = httplib2.Http()
    status, response = http.request(url)
    links = map(lambda link: link['href'],
                filter(lambda link: link.has_key('href'), BeautifulSoup(response, parseOnlyThese=SoupStrainer('a'))))
    attachments = list(set(map(lambda x: x.split("&")[0], filter(lambda x: "attachment" in x and "bugid" not in x and "id=" in x, links))))
    reviews = list(set(filter(lambda x: "code.wireshark.org/review" in x, links)))
    return attachments, reviews

def save_attachments(cve_id):
    def save(attachment):
        http = httplib2.Http()
        cve_dir = os.path.join(WIRESHARK_ATTACHMENTS, cve_id)
        if not os.path.exists(cve_dir):
            os.mkdir(cve_dir)
        attachment_file = os.path.join(cve_dir, attachment.split("id=")[1])
        status, response = http.request(attachment)
        with open(attachment_file, "wb") as f:
            f.write(response)
        return attachment_file
    return save


def get_wireshark_data(report):
    rep = report.split(",")
    cve_id= rep[0]
    info = map(lambda x: x.strip().replace("//","http://").replace('"',""), rep[-4].split("|"))
    bugs = map(bug_to_commit, filter(lambda x: "bugs.wireshark" in x, info))
    attachments, reviews = reduce(list.__add__, map(lambda x: x[0], bugs), []) , reduce(list.__add__, map(lambda x: x[1], bugs),[])
    attachments = map(lambda x: "https://bugs.wireshark.org/bugzilla/" + x.replace("&action=edit", ""), attachments)
    reviews = reviews + filter(lambda x: r"code.wireshark.org/review" in x, info)
    ind = 0
    res = []
    for attachment in map(save_attachments(cve_id), attachments):
        for commit in set(reduce(list.__add__, map(review_to_commit, reviews), [])):
            reproduce_data = [cve_id + "_" + str(ind), attachment, commit]
            print reproduce_data
            res.append(reproduce_data)
            ind = ind + 1
    return res


with open(CVE_FILE) as cve:
    vulnerabilities = list(cve.readlines())[12:]
    # vulnerabilities = list(cve.readlines())[78000:80000]
    wire = filter(lambda x: "wireshark" in x, vulnerabilities)
    clean_wire = map(clean, wire)
    reports = reduce(list.__add__, map(get_wireshark_data, clean_wire), [])
    with open(OUT_FILE, "wb") as out:
        out_csv = csv.writer(out)
        out_csv.writerows([["CVE", "FILE_NAME", "COMMIT"]] + reports)
    print reports
