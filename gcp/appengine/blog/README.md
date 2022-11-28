# OSV Blog

This folder contains the OSV blog. The blog is rendered using Hugo(https://gohugo.io/).

Follow the top level [contributing guide](https://github.com/google/osv.dev/blob/master/CONTRIBUTING.md)
for Hugo installation.

## Writing a new blog post

Posts are written using Markdown. During deploy, this is rendered into HTML.

```bash
$ hugo new posts/name-of-new-post.md
$ <your-editor> content/posts/name-of-new-post.md
```

This generates something like:

```markdown
---
title: "Name of New Post"
date: 2022-11-28T16:39:38+11:00
draft: true
author: Your Name
---
First paragraph.
<!--more-->

Blah blah.
```

The frontmatter section contains metadata about the post, such as the title and
your name. The `<!--more-->` marker is used to
[split summaries](https://gohugo.io/content-management/summaries/#manual-summary-splitting).

If `draft` is set to `true`, the post is not rendered or included by default.

## Testing changes

Run the appengine frontend by following the steps
[here](https://github.com/google/osv.dev/blob/master/CONTRIBUTING.md#ui), and
navigate to <https://localhost:8000/blog/>.
