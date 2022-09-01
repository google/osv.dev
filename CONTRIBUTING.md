# How to Contribute

We'd love to accept your patches and contributions to this project. There are
just a few small guidelines you need to follow.

## Contributor License Agreement

Contributions to this project must be accompanied by a Contributor License
Agreement. You (or your employer) retain the copyright to your contribution;
this simply gives us permission to use and redistribute your contributions as
part of the project. Head over to <https://cla.developers.google.com/> to see
your current agreements on file or to sign a new one.

You generally only need to submit a CLA once, so if you've already submitted one
(even if it was for a different project), you probably don't need to do it
again.

## Code reviews

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult
[GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
information on using pull requests.

## Community Guidelines

This project follows
[Google's Open Source Community Guidelines](https://opensource.google.com/conduct/).

## Contributing code

### Prerequisites
You must install:
1. Git
1. Python 3.8+
1. [Make](https://www.gnu.org/software/make/)
1. [Pipenv](https://pipenv.pypa.io/en/latest/)
1. [Google Cloud SDK](https://cloud.google.com/sdk)

Then you can set up the development environment by cloning the OSV repo and
installing the Pipfile dependencies.

```shell
$ git clone https://github.com/google/osv.dev
$ cd osv.dev
$ git submodule update --init --recursive
$ pipenv sync --dev
$ pipenv shell
```

### Running tests
Certain tests require you to auth with the Google Cloud SDK and to install
the Datastore Emulator:

```shell
$ gcloud auth login --update-adc
$ gcloud components install beta cloud-datastore-emulator
```

To run tests:
```shell
$ make all-tests
```

#### Test result generation

Many tests are written using a
[simple framework](https://github.com/google/osv.dev/blob/a4b682a32575cc3314a5ef83c8e91b70c60f7b77/osv/tests.py#L32)
to help with generating expected test outputs.

The expected outputs are generated once and saved into the source tree to run
all subsequent tests against.

If a change is made that requires these outputs to be regenerated, you can set
the environment variable `TESTS_GENERATE=1` and run the tests:

```shell
$ TESTS_GENERATE=1 make all-tests
```

### Linting and formatting
To lint your code, run

```shell
$ make lint
```

To format your code, run
```shell
$ yapf -i <file>.py
```

### Running local UI and API instances (maintainers only)

#### UI

```shell
$ gcloud auth login --update-adc
$ make run-appengine
```

#### API

Running a local instance of the API server requires service account
credentials.

You will need to download a service account key for `esp-test@oss-vdb.iam.gserviceaccount.com` from
<https://cloud.google.com/console/iam-admin/serviceaccounts?project=oss-vdb>. Keep this safe.

```shell
$ gcloud auth login --update-adc
$ make SERVICE_ACCOUNT=/path/to/service_account.json run-api-server
```
