# RAK3172_AES_Test

A small test showing how to do AES 128 (or 192, or 256) on a Wisblock RAK3172 – you could use it on RAK4631, but why bother, it has hardware encryption!

The CBC part runs twice, to show the effect of an Iv on encryption. As you can see the ciphertext is not the same, but decodes properly (fortunately!).

```
RAK3172 Software AES128 test!
Plain text:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|48 65 6c 6c 6f 20 75 73 65 72 21 20 54 68 69 73 | |Hello user! This|
 1.|20 69 73 20 61 20 70 6c 61 69 6e 20 74 65 78 74 | | is a plain text|
 2.|20 73 74 72 69 6e 67 21                         | | string!        |
   +------------------------------------------------+ +----------------+
pKey:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|54 68 69 73 5f 49 73 2d 41 20 4b 65 79 31 32 33 | |This_Is-A Key123|
   +------------------------------------------------+ +----------------+
ECB Encoded:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|1d a6 e5 03 e1 2f 1b 2f 79 67 7a d8 95 59 4b 34 | |....././ygz..YK4|
 1.|9d 8d c3 42 d4 c0 87 78 a8 9e b7 e3 cf 7d 60 56 | |...B...x.....}`V|
 2.|a6 c6 64 bb 75 19 d2 7e 77 db d3 2c ca 42 2a bb | |..d.u..~w..,.B*.|
   +------------------------------------------------+ +----------------+
1859 round / s
ECB Decoded:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|48 65 6c 6c 6f 20 75 73 65 72 21 20 54 68 69 73 | |Hello user! This|
 1.|20 69 73 20 61 20 70 6c 61 69 6e 20 74 65 78 74 | | is a plain text|
 2.|20 73 74 72 69 6e 67 21 00 08 08 08 08 08 08 08 | | string!........|
   +------------------------------------------------+ +----------------+
3010 round / s
IV:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|5f 21 62 02 f8 e7 4c 4c a7 b7 69 ae 78 5f 21 d6 | |_!b...LL..i.x_!.|
   +------------------------------------------------+ +----------------+
CBC Encoded:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|f9 d4 76 bb 19 68 73 3e 33 47 8e 93 cb ef 67 2d | |..v..hs>3G....g-|
 1.|ce 46 f5 15 52 2b 1b 38 36 b1 34 64 14 3f 45 bd | |.F..R+.86.4d.?E.|
 2.|16 50 c1 fa b8 a7 39 94 d7 bb f4 47 d7 84 68 08 | |.P....9....G..h.|
   +------------------------------------------------+ +----------------+
1836 round / s
CBC Decoded:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|48 65 6c 6c 6f 20 75 73 65 72 21 20 54 68 69 73 | |Hello user! This|
 1.|20 69 73 20 61 20 70 6c 61 69 6e 20 74 65 78 74 | | is a plain text|
 2.|20 73 74 72 69 6e 67 21 08 08 08 08 08 08 08 08 | | string!........|
   +------------------------------------------------+ +----------------+
1116 round / s
IV:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|5a 1f 38 d8 ae 80 4e 4b ad 2e 41 89 a3 62 08 2b | |Z.8...NK..A..b.+|
   +------------------------------------------------+ +----------------+
CBC Encoded:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|fe b6 08 f4 8d 5a a8 34 4d db e3 76 89 36 3a d9 | |.....Z.4M..v.6:.|
 1.|e7 d1 64 8d de cc 90 e4 4b 31 5e 7e e6 9e 83 55 | |..d.....K1^~...U|
 2.|70 9c 9b cd 35 00 0f f3 ef 24 8e 0c ce 70 6c 76 | |p...5....$...plv|
   +------------------------------------------------+ +----------------+
1836 round / s
CBC Decoded:
   +------------------------------------------------+ +----------------+
   |.0 .1 .2 .3 .4 .5 .6 .7 .8 .9 .a .b .c .d .e .f | |      ASCII     |
   +------------------------------------------------+ +----------------+
 0.|48 65 6c 6c 6f 20 75 73 65 72 21 20 54 68 69 73 | |Hello user! This|
 1.|20 69 73 20 61 20 70 6c 61 69 6e 20 74 65 78 74 | | is a plain text|
 2.|20 73 74 72 69 6e 67 21 08 08 08 08 08 08 08 08 | | string!........|
   +------------------------------------------------+ +----------------+
1117 round / s
```