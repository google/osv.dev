# README

The [OSV.dev docs](https://osv.dev/docs) are hosted on [GitHub Pages](https://pages.github.com/).

## Running docs locally (docker)

You can run the docs locally consistently through docker. From the `docs` directory, run:

```bash
docker build -t osvdev-docs -f docs.Dockerfile .
docker run -p 4000:4000 osvdev-docs
```

## Running docs locally (native)

To run the docs locally:

- Install `ruby (>= 3.1.0)`. This should come with `bundler`.
  - On Debian, you need to install them separately:
    - `ruby`
    - `ruby-bundler`
- In this directory:
  - `bundle install`
  - `bundle exec jekyll serve`

Here's the full documentation on GitHub for [running Jekyll locally].

[running Jekyll locally]: https://docs.github.com/en/pages/setting-up-a-github-pages-site-with-jekyll/testing-your-github-pages-site-locally-with-jekyll#building-your-site-locally

## OpenAPI generation

### Prerequisites

Install `protoc` for your platform:

https://grpc.io/docs/protoc-installation/

Install `clang` for your platform:

https://releases.llvm.org/download.html

In the root directory, update submodules:

```bash
git submodule update --init --recursive
```

Install `protoc-gen-openapiv2`:

```bash
go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2@latest
```

To install the protobuf service converter, run:

```bash
go mod download
```

### Generation

```bash
python3 ./build_swagger.py
```
