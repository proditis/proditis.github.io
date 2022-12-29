---
layout: research
title: Hacking tools for developers
category: research
date: 03/02/2022
toc: true
tags:
  - research
  - nginx
  - dev
  - hacking
---

The following document outlines the methodology we developed in order to utilize hacking and bugbounty tools to strengthen the security posture as well as robustness of our applications 😃

## How it all started
The drive behind all this, other than the fact that I find new techniques and methodologies fascinating, was the lack of testing tools that could be integrated into a CI/CD pipelines that have security in mind.

For our project, at echoCTF.RED, we don't only have to maintain the web interface codebases that we use, but we also have to maintain server and service configurations (such as nginx, pf, mysql etc).

So even though we may perform static source code analysis and source code reviews every so often, there is no way to integrate tools that could perform such static analysis for nginx configurations or pf configurations etc. Part of that testing includes utilizing similar tools that the pen-testing and bugbounty communities use on a daily basis and thus this research is started.

Hopefully by the end of this document/research we will also have a docker container ready to be deployed that will become part of our CI/CD pipelines to automatically check code and service configurations.

## Methodology outline
1. Static analysis of service configs and check for common (mis)configuration patterns for services utilized by our apps. This includes configuration checks for the following:
  a. NGINX configuration files: `gixy participantUI.conf`
  b. php.ini and php-fpm.conf (parse and check against recommended values)
  c. MariaDB (parse and check my.cnf settings)
2. Static Analysis of application source code (eg `phpcs echoCTF.RED/frontend`)
3. Penetration Testing on each of the individual services (eg nginx, mysql, php-fpm)
4. Penetration Testing on the application (eg the `echoCTF.RED/fronend`)
5. Functional testing of active configurations (eg confirm that rate limit on nginx works etc)