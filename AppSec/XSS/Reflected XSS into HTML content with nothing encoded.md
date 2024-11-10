```markup
Date: 2024-11-10
Platform: PortSwigger Academy
Difficulty: Practitioner
Author: Nguyen Nghia Hiep
```
## Description
This lab contains a simple reflected cross-site scripting vulnerability in the search functionality.
To solve the lab, perform a cross-site scripting attack that calls the `alert` function.

---
## Writeup
Testing the search function, showed that user input is reflected onto the page.
![](img/Pasted%20image%2020241110112609.png)
Analyze the context of the reflected input, we can see that it is between `<h1>` tags. 
![](img/Pasted%20image%2020241110113015.png)
Example payload.
```html
'</h1> <img src=x onerror=alert(1)>
```
The payload is successful and the malicious script is executed.
![](img/Pasted%20image%2020241110113422.png)
#XSS 