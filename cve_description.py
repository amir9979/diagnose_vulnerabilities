import csv

CVE_FILE = r"C:\Users\User\Downloads\allitems (5).csv"
OUT_FILE = r"C:\vulnerabilities\{PROJECT}_cves_description.csv"
HEADER = [["CVE ID", "Description"]]

CVES = {"librachive" : ["CVE-2015-8915", "CVE-2015-8918", "CVE-2015-8919", "CVE-2015-8920", "CVE-2015-8921", "CVE-2015-8922", "CVE-2015-8923", "CVE-2015-8924", "CVE-2015-8925", "CVE-2015-8926", "CVE-2015-8927", "CVE-2015-8928", "CVE-2015-8930", "CVE-2015-8932", "CVE-2015-8933", "CVE-2015-8934", "CVE-2016-10349", "CVE-2016-10350", "CVE-2016-4809", "CVE-2016-5844", "CVE-2016-6250", "CVE-2016-7166", "CVE-2016-8687", "CVE-2016-8688", "CVE-2016-8689"],
        "yara" : ["CVE-2016-10210", "CVE-2017-5924", "CVE-2017-8294", "CVE-2017-9304", "CVE-2017-9438", "CVE-2017-9438", "CVE-2017-9465", "CVE-2017-9465"],
        "imageworsener" : ["CVE-2017-7453", "CVE-2017-7454", "CVE-2017-7623", "CVE-2017-7939", "CVE-2017-7962", "CVE-2017-9204", "CVE-2017-9205", "CVE-2017-9207"],
        "jasper" : ["CVE-2016-10250", "CVE-2016-10251", "CVE-2016-8691", "CVE-2016-8692", "CVE-2016-8882", "CVE-2016-8883", "CVE-2016-8887", "CVE-2016-9388", "CVE-2016-9389", "CVE-2016-9393", "CVE-2017-6850"],
        "libtiff" : ["CVE-2015-8784", "CVE-2016-10092", "CVE-2016-10093", "CVE-2016-10095", "CVE-2016-10269", "CVE-2016-10270", "CVE-2016-10271", "CVE-2016-10272", "CVE-2017-5225"]}

with open(CVE_FILE) as cve:
    vulnerabilities = map(lambda x: x.split(","), list(cve.readlines())[12:])
    for project in CVES:
        cve_list = map(lambda x: [x[0], x[2]], filter(lambda x: x[0] in CVES[project], vulnerabilities))
        print project, len(CVES[project])
        with open(OUT_FILE.format(PROJECT=project), "wb") as out_file:
            writer = csv.writer(out_file).writerows(HEADER + cve_list)



