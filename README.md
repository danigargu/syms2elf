# syms2elf

The plugin exports all the symbols recognized by IDA Pro and only functions in radare2 to the ELF symbol table. This allows us to use the power of IDA/r2 in recognizing functions (analysis, FLIRT signatures, manual creation, renaming, etc), but not be limited to the exclusive use of this tools.

Supports 32 and 64-bits file format.

## INSTALLATION

  * **IDA Pro**: Simply, copy `syms2elf.py` to the IDA's plugins folder.
  * **radare2**: You can install via r2pm: `r2pm -i syms2elf`



## EXAMPLE

Based on a full-stripped ELF:

```
$ file test1_x86_stripped 
test1_x86_stripped: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, stripped
```

Rename some functions and global variables in IDA or funcitons in r2, run `syms2elf` and select the output file.

![IDA output log](https://cloud.githubusercontent.com/assets/1675387/13477862/a02aa742-e0ce-11e5-835e-3a0992a3f171.png)

![r2_syms2elf](https://cloud.githubusercontent.com/assets/1675387/13831270/adddfae2-ebd2-11e5-8dcd-877c9c67faed.png)

After that:

```
$ file test1_x86_unstripped 
test1_x86_unstripped: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, not stripped
```

Now, you can open it with others tools and analyzing in a more comfortable way.

## AUTHORS

  * Daniel García (@danigargu)
  * Jesús Olmos (@sha0coder)
  * Kirill Magaskin (@K1RPI7CH)

## CONTACT 

Any comment or request will be highly appreciated :-)
