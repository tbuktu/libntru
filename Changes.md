
Modifications on Sun Jul 16 19:44:38 MDT 2017

Added check for `__clang__` in a number of files so that this will compile with the
standard cc shipped with MacOS.

Fixed problem #37 with it not working on MacOS due to incorrect extern's for 
global variables.

TODO: Because it is not using special instructions in CLang it is much slower.

