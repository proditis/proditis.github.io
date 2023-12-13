---
layout: post
title: Run Gitbook locally
category: blog
tags:
  - Gitbook
  - Markdown
  - Howto
---

As part of maintaining large numbers of markdown files, I need a way to perform tests (see how the look) before I publish (ie Github Pages, Gitbook etc).

The nodejs packages for gitbook are a bit outdated but with the following steps i am able to have a working version running locally.

```
npm init -y
npm install gitbook --save-dev
npm install gitbook-cli --save-dev
cd node_modules/gitbook-cli/node_modules/npm/node_modules
npm install graceful-fs@latest --save
```
