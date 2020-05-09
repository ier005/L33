---
title: "使用Github Actions自动部署Hugo至Github Pages"
date: 2020-04-20T09:07:44+08:00
categories: [Misc]
draft: false
---

## 生成repo的token

首先需要在个人设置中生成GitHub token，并将其添加到对应repo，在下述的Github Actions配置文件中引用，以使得自动构建能够推送生成的静态文件至repo中。


## 添加workflow

在hugo项目根目录中新建`.github/workflows/gh-pages.yml`，内容如下：

```yaml
name: github pages

on:
  push:
    branches:
      - master

jobs:
  deploy:
    runs-on: ubuntu-18.04
    steps:
      - uses: actions/checkout@v2
        #with:
        #  submodules: true  # Fetch Hugo themes
        #  fetch-depth: 0    # Fetch all history for .GitInfo and .Lastmod

      - name: Setup Hugo
        uses: peaceiris/actions-hugo@v2
        with:
          hugo-version: '0.68.3'
          extended: true

      - name: Build
        run: hugo --minify

      - name: Deploy
        uses: peaceiris/actions-gh-pages@v3
        with:
          github_token: ${{ secrets.TOKEN }}
          publish_dir: ./public
          cname: blog.usec.cc
```

修改`github_token`的名称，如果需要，修改对应配置，如hugo版本，是否拉取theme新版本等。

默认推送至当前repo的`gh-pages`分支中，可自定义。





---

参考：

[actions-hugo](https://github.com/peaceiris/actions-hugo)