---
title: "Introducing broad C/C++ vulnerability management support"
date: 2023-11-01T00:10:00Z
draft: false
author: Andrew Pollock and Oliver Chang
---
OSV is committed to bringing our users comprehensive, accurate and timely open source vulnerability information. Over the last year, we’ve released a number of new features in pursuit of this goal including:
- [OSV-Scanner’s call graph analysis for Go and Rust](https://google.github.io/osv-scanner/experimental/#scanning-with-call-analysis)
- Adding six new ecosystems to the database
- [The determineversion API](https://osv.dev/blog/posts/using-the-determineversion-api/), which expanded access to C/C++ vulnerabilities for OSS-Fuzz projects 

Today we are announcing that OSV advisories now include vulnerable commit ranges. **Vulnerable commit ranges, along with the previously announced experimental determineversion API, will enable vulnerability management for software with C and C++ dependencies, which has been one of the last gaps in coverage in OSV.dev’s database. Additionally OSV-Scanner is now compatible with C and C++ projects.**
<!--more-->

Because the C/C++ ecosystem doesn’t have a centralized package registry, source code identifiers (e.g. git hashes) are the best way to identify C/C++ libraries. Typically, vulnerabilities are associated with versions, not Git hashes, making C/C++ vulnerability matching difficult. The new commit level vulnerability information will allow users to confidently match their dependencies to known vulnerabilities within the OSV database. 

Vulnerable commit ranges provide a granular approach that more closely follows the development process, matching vulnerabilities to a range of upstream commits instead of matching vulnerabilities to a package version. This precise information allows for accurate identification of Git branches cut from known vulnerable commits and leads to more accurate vulnerability information.

## How are vulnerable commit ranges included in the OSV database?

We’ve enriched over 30,000 advisories based on the [NVD CVE database](https://nvd.nist.gov/vuln/search). We’ve added vulnerable commit ranges to these advisories by using algorithmic analysis to match Git repository tag information to patch information supplied by the NVD CVE entry. 

As part of our work in this area, we've established working relationships with the NVD via data quality fixes and longer term systematic improvements.

![Image shows the vulnerable commit ranges for CVE-2023-26130. More information is available in the "Submoduled C/C++ dependencies" section.](commit-range.png "Vulnerable commit ranges for CVE-2023-26130")
[Sample OSV advisory](https://osv.dev/vulnerability/CVE-2023-26130) with commit range information.

## Finding C/C++ vulnerabilities with vulnerable commit ranges

Matching C/C++ dependencies to known vulnerabilities has been one of the final pieces in the puzzle of a truly comprehensive open source vulnerability database. Most projects with C/C++ dependencies include a copy of those dependencies bundled with the project, either by using submodules or by vendoring dependencies. Whether dependencies are submoduled or vendored, vulnerable commit ranges allow OSV users to match their dependencies to known vulnerabilities. 

### Submoduled C/C++ dependencies

Submoduled dependencies retain their Git histories. [OSV-Scanner](https://google.github.io/osv-scanner/) [v1.4.3](https://github.com/google/osv-scanner/releases/tag/v1.4.3) is able to determine the most recent Git commits for the submoduled dependencies and return any associated vulnerabilities. 

For example, let’s consider the [yuzu](https://github.com/yuzu-emu/yuzu) project and see if we can find any vulnerabilities in the project dependencies. We’ll be working from commit `43be2bfe332d5537041262eb08037993239eaf5f` for this example. 

Follow these steps:

1. Clone the yuzu project to your local machine using `git clone https://github.com/yuzu-emu/yuzu`. It is not necessary to use `git clone –recursive`. OSV-Scanner will be able to determine the appropriate Git commits without the recursive flag. 
2. Checkout the relevant commit using `git -C yuzu checkout 43be2bfe332d5537041262eb08037993239eaf5f`
3. Run `osv-scanner yuzu/`

OSV-Scanner returns the following vulnerabilities from the submoduled dependencies:

- [CVE-2023-26130](https://osv.dev/vulnerability/CVE-2023-26130) from cpp-httplib
- [CVE-2021-28429](https://osv.dev/vulnerability/CVE-2021-28429) from ffmpeg

Fortunately both cpp-httplib and ffmpeg have fixes for these vulnerabilities and yuzu has updated its copies of these dependencies. The yuzu project is no longer vulnerable to CVE-2023-26130 or CVE-2021-28429.

### Vendored C/C++ dependencies

Vendored dependencies are included in a project by simply copying the code into the repository. Git commit information is not retained, so we need another way to determine whether a vulnerability is present. In these cases, OSV-Scanner uses the [determineversion API](https://google.github.io/osv.dev/post-v1-determineversion/) to estimate each dependency’s version (and associated commit), and match it to any known vulnerabilities. 

When we [released the API](https://osv.dev/blog/posts/using-the-determineversion-api/) in July, its use was limited to vulnerabilities found by [OSS-Fuzz](https://google.github.io/oss-fuzz/). Not all C/C++ projects are part of OSS-Fuzz, nor are all vulnerabilities for a given dependency found by OSS-Fuzz, so a number of vulnerabilities were left on the table. With the addition of the commit level vulnerability data from the NVD, this gap has been significantly narrowed. **This means that the determineversion API, and the associated OSV-Scanner functionality, can now be used for the majority of vendored C/C++ dependencies.** 

Let’s consider the [OpenCV](https://github.com/opencv/opencv) project, which uses vendored dependencies. Working from commit `e9e6b1e22c1a966a81aca1217b16a51fe7311b3b`, OSV-Scanner is able to find a number of vulnerabilities from the vendored dependencies including:

- [CVE-2021-29390](https://osv.dev/vulnerability/CVE-2021-29390) from libjpeg 
- [CVE-2022-3857](https://osv.dev/vulnerability/CVE-2022-3857) from libpng 
- [CVE-2023-3618](https://osv.dev/vulnerability/CVE-2023-3618) from libtiff 
- [CVE-2020-11760](https://osv.dev/vulnerability/CVE-2020-11760) from openexr
- [OSV-2022-416](https://osv.dev/vulnerability/OSV-2022-416) from openjpeg
- [CVE-2022-3509](https://osv.dev/vulnerability/CVE-2022-3509) from protobuf

## Try it yourself!

Do you have a project that uses C/C++ dependencies? We encourage you to try our new vulnerable commit range features by using the [latest OSV-Scanner release](https://github.com/google/osv-scanner/releases/tag/v1.4.3) and [let us know](https://github.com/google/osv.dev/issues/new/) about your experience. If you encounter a data issue, please fill out a [data quality report](https://github.com/google/osv.dev/issues/new?assignees=&labels=data+quality&projects=&template=converted-nvd-cve-data-quality-report.md&title=Data+quality+issue+with+CVE-yyyy-nnnn). Your contributions, questions, and feedback will help us improve not only the quality of our data, but will ultimately help users identify and fix vulnerabilities in their projects. 
