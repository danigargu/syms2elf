# syms2elf

The plugin export the symbols (for the moment only functions) recognized by IDA Pro and radare2 (also works for rizin and cutter) to the ELF symbol table. This allows us to use the power of IDA/r2 in recognizing functions (analysis, FLIRT signatures, manual creation, renaming, etc), but not be limited to the exclusive use of this tools.

Supports 32 and 64-bits file format.

## INSTALLATION

  * **IDA Pro**: Simply, copy `syms2elf.py` to the IDA's plugins folder.
  * **radare2**: In radare2 environment, pass this command: `#!pipe python ./syms2elf.py <output_file>`
  *  **rizin** : In rizin environment, pass this command: `#!pipe python ./syms2elf.py <output_file>`
  * If you are using radare2, make sure that you have install r2pipe. You can use this command: `pip3 install r2pipe`
  * For rizin: `pip3 install rzpipe`



## EXAMPLE

Based on a full-stripped ELF:

```$ file test_x86 
testfile_x86: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=7ee4206d91718e7b0bef16a7c03f8fa49c4a39e7, stripped
```

Rename some functions in IDA or r2, run `syms2elf` and select the output file.

![IDA output log](https://cloud.githubusercontent.com/assets/1675387/13477862/a02aa742-e0ce-11e5-835e-3a0992a3f171.png)

![r2_syms2elf](https://user-images.githubusercontent.com/40752497/181514837-0fe5de8a-29db-4a67-a614-f10a773b5e1c.png)

![cutter](https://user-images.githubusercontent.com/40752497/181536360-f725857c-1893-48c4-ac4a-96288a034b31.png)


After that:

```
$ file test_x86_unstripped 
test_x86_unstripped: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=7ee4206d91718e7b0bef16a7c03f8fa49c4a39e7, not stripped
```

Now, you can open it with others tools and analyzing in a more comfortable way.

## AUTHORS

  * Daniel García (@danigargu)
  * Jesús Olmos (@sha0coder)
  * Ivan Stupnitskiy (@YanagiRu) -- plugin porting
## CONTACT 

Any comment or request will be highly appreciated :-)

## AND ALSO
This modification (plugin porting to rizin & cutter) was started as a part of [Digital Security](https://github.com/DSecurity)'s Research Centre internship ["Summ3r of h4ck 2022"](https://dsec.ru/about/vacancies/#internship).
