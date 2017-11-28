import os
import json
import subprocess


REPRODUCE_PATH = r"C:\vulnerabilities\reproduce"
GIT_CLONE = r"git clone https://github.com/{owner}/{repo}.git {dir_name}"
LS = r"git ls-files"
CMAKE = "CMakeLists.txt"
SLN = ".sln"

if __name__ == "__main__":
    j = json.load(open(r"C:\temp\data4.json"))
    sor = sorted(map(lambda x: (x[0], len(x[1])), j.items()), key=lambda x: x[1])
    filtered = filter(lambda x: x[1] > 3, sor)
    good_projects = set()
    for owner, repo in map(lambda x: eval(x[0]), filtered):
        # p = subprocess.Popen(GIT_CLONE.format(owner=owner, repo=repo, dir_name=os.path.join(REPRODUCE_PATH, repo)).split())
        # p.wait()
        p = subprocess.Popen(LS.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=os.path.join(REPRODUCE_PATH, repo))
        stdoutdata, stderrdata = p.communicate()
        for line in stdoutdata.split():
            if CMAKE.lower() in line.lower() or SLN.lower() in line.lower():
                good_projects.add(str(repo))
    with open(os.path.join(REPRODUCE_PATH, "good.json"), "wb") as f:
        json.dump({"good": sorted(list(good_projects))}, f)



