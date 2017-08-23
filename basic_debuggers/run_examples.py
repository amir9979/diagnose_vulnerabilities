
if __name__ == "__main__":
    # run_examples_on_project(sys.argv[1], sys.argv[2])
    # exit()
    run_examples_on_project(r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5509\vulnerable\ImageMagick-Windows\VisualMagick\bin\magick.exe",
                            r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5509\fuzzing", None)
    exit()
    run_IM_on_images(r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5509\vulnerable\ImageMagick-Windows\VisualMagick\bin\magick.exe",
                  get_images(EXAMPLES_PATH) +
                     [r"C:\vulnerabilities\ImageMagick_exploited\CVE-2017-5509\fuzzing\seedfiles\5.psd"],
                     r"C:\Temp\examples", None)
