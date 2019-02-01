# Various approach to automate to a reversing challenge

## **Introduction**
In this writeup I would introduce some ways to approach by scripting and automate, with different tools, a reverse engineer challenge.

The target people are they who doesn't know much about automate a reversing challenge but knows something on reversing engineering in general, the scripts I will show in this file are only introductive

The challenge we are going to see was one of the practice challenges for Reply Cyber Security Challenge.
The challenge name is ***wysiNwyg*** and I choose it because of it's "semplicity" to be scripted.

The tools I'm going to introduce are:
- [Cutter](https://github.com/radareorg/cutter) (for static analysis)
- [gdb-peda](https://github.com/longld/peda)/[gdb-gef](https://github.com/hugsy/gef)
- [R2pipe](https://github.com/radare/radare2-r2pipe)
- [frida](https://www.frida.re/) (alla fine non credo di trattarlo, al momento comunque non c'è)

## **Binary Analysis**
First of all, try to run strings to see if we found something useful:
```
$ strings ./wysiNwyg
...
ptrace
...
No debugger please!
#########################################################
### Welcome to the "wysiNwyg" challenge!
###     Your task is to find out the password to be able
###     to decrypt the password-protected zip and read
###     the secret flag. Good Luck!!
#########################################################
Password: 
s3cR3t_p4sSw0rD
This is not the solution you are looking for :)
Try again :(
...
```

All right!! We just discover that there is a call to **ptrace** and it looks like that it doesn't want to be debugged.
Now we can open ***Cutter*** and start to understand what it does.

One of the first things I noticed is that there are 4 ['init' and 'fini' functions](http://l4u-00.jinr.ru/usoft/WWW/www_debian.org/Documentation/elf/node3.html), two of them .init and the others two .fini, and the entry4.fini is much bigger than every other functions. But start in order by analyzing the first one and it seems that it doesn't do anything significant, so we can pass to entry2.init

![entry2_img](images/entry2_img.png)

OK! We found where the ptrace is called, now we can patch the binary using.. the power of Cutter 😎

![nop_ptrace](images/nop_ptrace.png)

Now we can start to analyze the main function.
It's easy to see that, after the welcome message and the 'Password: ' string, there ia *fgets* that takes at most **35** chars in input and stores them at ```0x8049d60```.

![img_fgets](images/img_fgets.png)

To see better the flow of the function I decided to use **graph view**:
![graph_main](images/graph_main.png)

It seems that the first thing it does is checks if the input is empty, and in that case jump directly to the end, otherwise it continues by removing the last char if is a '\n' and compare the string with "*s3cR3t_p4sSw0rD*", but this comparison was only a troll.. The last thing the program checks in the main is if the string has 34 lenght chars (0x22) and if not prints "*Try again :(*".

Good, now we know that the program wants a 34 lenght string, but which?
Let's go to analyze the fini's functions.
I'll skip the entry3.fini function because it won't lead to nothing important.

entry4.fini instead is the function we are looking for. First, after a declaration of many variables that we skip at the moment, it checks again if strings has lenght 34 to go to start a cicle.
Excellent! This is where we can find our answer!
With graph view we can easely see that the cicle will end either the program has done 33 cicles or if miss a compare.

![snippet_while](images/snippet_while.png)

Here the program take each char of our string, xor them with 51 (0x33) and compare them with another string.
So what we need to do now then is put a breakpoint at the compare. take the value inside edx, xor it with 51 and finally reconstruct the password.
If the program correctly end the cycle it goes in another while where I guess (because of the ```call sym.imp.putchar```) it will print a congratulation message.
But...do we want to do it by hand?

## **Time to script!**
Before we saw how the program wants a password which has lenght 34 and were it seems to checks it.
The address where is the compare is ```0x0804872e```.

What I want now is to build a script that breaks at ```0x0804872e```, picks the value of edx (and possibly xor it with 51) and set eax = edx so that it can pass the compare and continue the cycle.

### GDB
To run a GDB script we need to write all the commands in a file and load it by running gdb with ```-x filename``` option, as you can see on the first line of the next code.

Breakpoints can be set before the list of commands and if are needed here we can also set variables.

A solution with GDB is the following:
```
#gdb -silent -x ./gdbinit ./wysiNwyg    # command to run gdb using this script

b* 0x0804872e                   # put a breakpoint at the compare
commands                        # start list of the list of commands to do

p/x $edx^51                     # print the hex value of edx^51
set $eax = $edx                 # set eax = edx so that it can pass the compare
continue                        # continue the execution, if it's all right it will hit the breakpoint 34 times
end                             # end of list of commands

run                             # start the execution
```

Remember to input a random string which has lenght >= 34, if it's shorter it will end before the compare, if it's longer no problem in fact the fgets will take only 35 chars.

The output this script will be the list of all values in edx:
```
$1 = 0x2
$2 = 0x5d
...
$32 = 0x6a
$33 = 0x12
$34 = 0x12
Congratulations! You just won :p
```
Ok, we managed to win..but...the password?...we have two options either write a program that takes that values and reconstract the string or let gdb do that for us!
So, instead of doing ```p/x $edx^51``` I opted to use the printf:

```printf "%c", ($edx^51)```

Run gdb again and:
```
...
1n1T_4nD_F1n1_4rR4Ys_4r3_S0_34sY!!Congratulations! You just won :p
...
```

We got it!!!

These two examples were only to introduce you to scripting, in fact if we use some extension to GDB this challenge could be easily solved.
Below I will show my solutions using GDB-peda (with ```xormem```) and GDB-gef (with ```xor-memory```)

#### GDB-peda
When I have analyzed the entry4.fini function I skipped  the declaration of many variables, they were probably the encrypted password and congratulaton message, with the following scripts I try to decrypt them directly from the memory.

Unfortunately for an unknown reason we couldn't put a number as key in any ways, so we have to append a char so that it didn't "think" it is a number...
So I decided to xor the chars in an even position and after those who are in odd one:
```
source ~/peda/peda.py

#set a breakpoint immediatly after the declaration of the variables
b* 0x080486e9

commands

xormem $ebp-0x50 $ebp-0x0d "\x33\x00"   # xor chars in an even position
xormem $ebp-0x50 $ebp-0x0d "\x00\x33"   # xor chars in an odd position

# print the result as string
x/s $ebp-0x50

continue
end
run
```

#### GDB-gef
The same script for GDB-gef is instead:
```
source ~/gef/gef.py

#set a breakpoint immediatly after the declaration of the variable
b* 0x080486e9

commands

xor-memory display $ebp-0x50 67 "\x33"

continue
end
run
```

Don't forget to do ```help [command]``` if you don't know what a command does!

For a cheatsheet of GDB-peda's commands see [here](https://github.com/stmerry/gdb-peda-cheatsheet/blob/master/gdb-peda%20cheatsheet.pdf).

For a cheatsheet of GDB-gef's commands see [here](https://github.com/zxgio/gdb_gef-cheatsheet/blob/master/gdb_gef-cheatsheet.pdf).

### R2pipe
R2pipe is a powerful tool because it integrates radare2 and python, so we can build more complex scripts.
It creates a sort of 'pipe' with which send commands and receive the result.

I used also rarun2 to redirect I/O to another terminal, an easy and useful guide on how to do is [here](https://reverseengineering.stackexchange.com/questions/16428/debugging-with-radare2-using-two-terminals).

In our R2pipe scripts we need first to load the binary with ```r2pipe.open()```, that takes as arguments the path to binary to load and the list of options with radare2 has to open the file. It will return an object "connected" with radare2.

After that all the commands we want to send to radare2 has to be "sent" with the ```cmd``` method of the object or, if we want a result parsed in JSON, with ```cmdj```.

The script I made for this presentation is the following:
```
#python R2p.py 2> /dev/null                         # command to run without showing 

import r2pipe
l = ['-d', '-e', 'dbg.profile=t.rr2']
p = r2pipe.open('./wysiNwyg', l)                    # load the binary using
s = ''
p.cmd("db 0x0804872e")                              # set a breakpoint at the compare
for i in range(34):
  p.cmd("dc");                                      # "debug continue", it will run until hit a breakpoint or it ends
  try:                                              # if it can't get the registers values it will throw an exception
    edx = p.cmdj("drj")['edx']                      # drj returns a json of the register's values,
                                                    # and I need only edx
  except:
    break
  p.cmd("dr eax=edx")                               # set eax = edx so it can pass the compare
  s += chr(edx^0x33)                                # reconstract the password
  
print s                                             # print us the password
```
As before input a random string with lenght >= 34







Thanks to *@zangobot* to help me to write this file