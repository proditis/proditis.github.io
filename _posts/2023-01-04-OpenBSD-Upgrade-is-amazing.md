---
layout: post
title: OpenBSD Upgrade is amazing
category: blog
tags:
  - OpenBSD
---

Ok i'll admit that in all the years i'm using OpenBSD i never once performed a "usable" upgrade. I've done my fair share of "tests" but never had a use of the systems i was upgrading so there was not an objective opinion on how well it works.

{:refdef: style="text-align: center;"}
![image tooltip here]({{site.baseimg}}/images/puffy72.gif)
{: refdef}

## how did you manage without upgrades?
In general my procedure with openbsd was always to focus on setting new servers fast rather than restoring them fast. My concept was that if its faster to setup a brand new server than it is to restore a backup or upgrade, then focus on been able to bring back fresh servers fast.

Ofcourse this "philosophy" is not advisable, we didn't have that many changing components so even a week old backup was up2date 99% of the times. We had the mechanisms in place to deal with the nuances of our use cases and thus were able to adapt our processes around that. The truth is that in most cases, we didnt even _restore_ data in the common sense.

## what changed?
So having said that, what made me actually try it in a usable situation was that
* there was a "change" of the time rule. The system that i wanted to work had a far more time consuming installation procedure.
* it was a _staging_ server and that i needed to test the newer version of OpenBSD (7.2)
* it was really late at night and i was kinda bored of doing the clean install, so i figured i have nothing to loose

I will still have to create clean install procedure for the system but assuming that the usual OpenBSD mantra of everything _just works (tm)_ i will have saved a lot of time :D

## so how did it went?
So the upgrade procedure was scarily simple!!! Just choose the `upgrade` option from the install media and everything else just sort of happens...

After the upgrade completes you reboot into a working system and you go over a `sysmerge` and `pkg_add -u`.

Out of everything the only command that sort of "scared" me was `sysmerge`. A lot of information to digest on such a "dangerous" command but still keeping my calms and following the onscreen instructions was enough. If i had a wish out of this it would have been a better merge option.

Other than that, it went amazingly well considering i jumped a few years ahead... what i havent mentioned was that i upgraded an OpenBSD 6.5 to 7.2
I needed to perform a few commands by hands with regards to PHP
* `pkg_add pecl74-memcached` (the `pecl71-memcached` package that it was installed did not get updated)
* `cp /etc/php-7.1/*.ini /etc/php7.4/` quick and dirty re-activate the needed php modules command :rofl:
* fix some chroot library issues (`/usr/local/lib/libintl*so*`,`/usr/local/lib/libicu*so*`,`/usr/local/share/icu/71.1`)
* remove some of the old packages that failed to update `pkg_delete pecl71-memcached`

After a quick reboot, the system was up and i was ready to continue my development. Whats more? In the time it took to upgrade i had also kept this blog post.

A big thank you to the OpenBSD developers. WOW the upgrade process is simply spectacular :clap: :heart: :blowfish:
