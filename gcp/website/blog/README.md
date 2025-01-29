# OSV Blog

This folder contains the OSV blog. The blog is rendered using
[Hugo](https://gohugo.io/).

Follow the top level
[contributing guide](https://github.com/google/osv.dev/blob/master/CONTRIBUTING.md)
for Hugo installation.

## Writing a new blog post

Posts are written using Markdown. During deploy, this is rendered into HTML.
The name of the file corresponds to the URL slug.

The file name must only container these regex characters `+\w-`.

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

## Posts with images

If you want to use images in your blog post, please do the following. 

1. Create a folder in this form: `content/posts/deisred-url-slug-for-post`
2. Move the markdown file you created into this folder and rename the markdown file to `index.md`. 
3. Any images in your post should be included in `content/posts/desired-url-slug-for-post`
4. Add images to your post in this format:
```
![Alt text for screen readers.](image-name.png "This text appears when the mouse hovers over the image.")
```

## Testing changes

Run the website frontend by following the steps
[here](https://github.com/google/osv.dev/blob/master/CONTRIBUTING.md#ui), and
navigate to <!-- markdown-link-check-disable-line --> <http://localhost:8000/blog/>.
