```markup
Date: 2024-11-10
Platform: PortSwigger Academy
Difficulty: Practitioner
Author: Nguyen Nghia Hiep
```
## Description
This lab contains a stored cross-site scripting vulnerability in the comment functionality.
To solve this lab, submit a comment that calls the `alert` function when the blog post is viewed.

---
## Writeup
Contains commenting functionality, where name, comment parameters are returned (the website will be the the hyperlink URL for name).
![](img/Pasted%20image%2020241110123358.png)

There are some client-side controls for email and website parameters (website must contain http or https strings, email must be of type email).

![](img/Pasted%20image%2020241110123611.png)

Information of the POST form is rendered on page like this, contained in between `<p>` tags.

![](img/Pasted%20image%2020241110123819.png)
HTML injection for name and comment parameters (comment parameter, renders the HTML tag, while the name parameter doesn't).
![](img/Pasted%20image%2020241110124440.png)
XSS payload on the comment parameter.
```html
<img src=x onerror=alert(1)>
```
![](img/Pasted%20image%2020241110125053.png)
### Attempts and other findings
- Since some parameters were controlled on the client-side, I attempted to remove them then add my payload, however, this failed.
- Website parameter can be bypassed through client-side.
- 
