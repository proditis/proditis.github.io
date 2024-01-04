---
layout: post
title: Install Skype on Linux Mint
category: blog
tags:
  - Howto
  - Linux
  - Mint
  - Skype
---

## Install from deb
Grab the latest deb (at this time is `skypeforlinux_8.110.76.107_amd64.deb`) directly from https://repo.skype.com/deb/pool/main/s/skypeforlinux/


## Install with snap
Install snapd

1. Remove or backup the file `mv /etc/apt/preferences.d/nosnap.pref /etc/apt/preferences.d/.disabled.nosnap.pref`
2. `apt-get update`
3. `apt-get install snapd`

