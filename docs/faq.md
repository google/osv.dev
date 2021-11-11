## Why did you create OSV?

We created OSV to address some of the shortcomings of dealing with
vulnerabilities in open source software.

As believers of automation, we initially built OSV for our
[OSS-Fuzz](https://github.com/google/oss-fuzz) service, where we needed a way to
store, triage and query the large numbers of open source vulnerabilities we
discover in an automated and precise fashion. Since then we have expanded this to include
vulnerabilities in many more open source ecosystems.

See our blog posts for more details:
- <https://security.googleblog.com/2021/02/launching-osv-better-vulnerability.html>
- <https://security.googleblog.com/2021/06/announcing-unified-vulnerability-schema.html>

## Who is OSV for?

OSV can be used by both:

- Open source consumers: By querying our API to find vulnerabilities in their
  dependencies.

- Open source maintainers: By using our automation infrastructure to
  determine accurate affected commits and versions when a vulnerability is
  fixed. Currently this works for bugs found by OSS-Fuzz, but we are working to
  make this more generally available.

## How does OSV compare to the existing CVE process?

We plan to aggregate existing vulnerabilities feeds (such as CVEs). OSV
complements CVEs by extending them with precise vulnerability metadata and
making it easier to match a vulnerability to a package and set of vulnerable
versions.

## Where does the data come from?

Please see the above "What is OSV" section!

## How are vulnerabilities represented?

All our vulnerabilities are described in a [simple, open format] easily used by
automation tools. This format is also intended to be easily human-editable and
used for interoperability with vulnerability sources.

[simple, open format]: https://ossf.github.io/osv-schema/

## How can I help onboard a new source of data?

Please let us know of your interest via either our [issue tracker](https://github.com/google/osv/issues)
or the [mailing list](https://groups.google.com/g/osv-discuss). The process generally 
involves exporting the vulnerability data in the [OSV format](https://ossf.github.io/osv-schema/).

## I'm a project maintainer. Can I edit the details of OSV entries for my project?

OSV is not the source of truth for most vulnerability data. To edit the details
of a particular entry, please contact the source of the vulnerability entry. In
many cases this is a community owned vulnerability database where you just need
to create a pull request.
