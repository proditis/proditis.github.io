---
layout: page
title: Thoughts on CVE
category: thoughts
date: 17/04/2022
---

# Thoughts on CVE

These are some thoughts on the subject of CVE's that arose by observing new high severity CVE's being assigned to applications almost nobody uses.

This is still not formalized completely as i like it to be but the gist of it goes like this.

Separate the vulnerability disclosure from the vulnerability exposure and vulnerability scoring system.
  - A CVD ID keeps track of the vulnerability disclosures (IDs) of all vulnerabilities disclosed and attributed to their original researcher
  - A CVE includes the actual exposure of the bug based on (eg 0 for applications that are used by 2 persons only)
  - The CVSS keeps the score as is
This gives us the opportunity to track CVE's based on their actual EXPOSURE score and not the severity of their CVSS.
