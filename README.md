# Simple Jail

NOTE: Don't rely on this tool for security purposes; it is only a proof of concept.

A command line tool that runs another executable, while only allowing writes to a user-specified list of directories and files.

ANOTHER NOTE: This tool relies on the landlock feature introduced in Linux version 5.13. Some file-related syscalls may not be currently restricted, yet (such as stat(2)). Executables that run with special permissions (such as `fusermount`) will not work either becuase of the privilege restrictions set by `prctl`. Check <https://landlock.io/> for more details.

## Purpose

This command line tool can be useful for restricting other processes from writing to files that you don't want written to.

I made this because I wanted a simple command line tool that can restrict build scripts from overwriting my hard drives.

Sometimes, the `root` user is needed in a build script, usually for tasks relating to disks or file systems. One example is a script that writes an operating system image to a USB stick. While the `root` user is necessary to run these tasks, it adds the possibility that the wrong drive is selected, which could overwrite your real hard drives. This could be caused by a typo of the wrong device name or a faulty script that uses the wrong device name.

Running these volatile build scripts under `sjail` would prevent any accidental or malicious writes to my real hard drives. This can be similarly done for any other files that you don't want a build script to overwrite. 

This concept exists in other similar jail programs, but I wanted one that is simple enough for me to understand in its entirety.

## Building

Just run `make` to build.

Only GCC, Make, and Linux 5.13 are required as prerequisites.

## Running

Here's the current command line interface:

```
./sjail [OPTIONS] ALLOWED_FILES ... -c COMMAND [ARGS ...]
```

The `-c` flag signals that the next argument will be a process to run under `sjail`. Arguments for this process can be listed after the process' path.

NOTE: Currently, the `COMMAND` needs to be in path form or it won't be run. So you can't run `truncate`, you have to run `/bin/truncate`.

## Examples

TODO: Include an example that prevents `root` user from overwriting disks in a script.

### Short Example

This example prevents the command `truncate` from writing to any directory except for either the current directory or `/tmp`.

Both attempts to write to `evil.txt` are denied in this example because it is not below any allowed directory.

The attempt to write to `not_evil.txt` succeeds because it is below the current directory, which is passed as an `ALLOWED_FILES` argument.

``` shellsession
$ ./sjail . /tmp -c /bin/truncate -s 6 ../evil.txt
/bin/truncate: cannot open '../evil.txt' for writing: Permission denied
$ ./sjail . /tmp -c /bin/truncate -s 6 ~/evil.txt
/bin/truncate: cannot open '/home/user/evil.txt' for writing: Permission denied
$ echo $?
1

$ ./sjail . /tmp -c /bin/truncate -s 5 not_evil.txt
$ echo $?
0
$ ls
not_evil.txt  examples  Makefile  README.md  sjail  sjail.c
$ du -b not_evil.txt
5       not_evil.txt
```

### Long Example

#### Safe Script

Say you are running a script that should only write to files beneath the current directory and not any outside of it. Here's an example of such a script:

``` shell
#!/bin/bash
# Found in 'examples/truncate_safe.sh'
truncate -s 5 ./not_evil.txt
```

That script truncates the file './not_evil.txt' to 5 bytes and creates the file if it doesn't exist. This is how the script should run normally:

``` shellsession
$ ls
examples  Makefile  README.md  sjail  sjail.c
$ ./examples/truncate_safe.sh
$ ls
not_evil.txt  examples  Makefile  README.md  sjail  sjail.c
$ du -b not_evil.txt
5       not_evil.txt
```

As you can see, it created the file 'not_evil.txt' in the current directory and truncated it to 5 bytes.

#### Evil Script

But what if someone changed the script without your knowledge to edit files in your home directory? Here's an example of this occurring:

``` shell
#!/bin/bash
# Found in 'examples/truncate_evil.sh'
truncate -s 5 ./not_evil.txt

# Evil part tries to truncate a file in the home directory
truncate -s 6 ~/evil.txt
```

Running this script normally would successfully write to the evil file in the user's home directory, without the user's knowledge.

#### Restrict Evil Script

However, this can be prevented with `sjail` by listing only the current directory as allowed:

``` shellsession
$ ./sjail . -c ./examples/truncate_evil.sh
truncate: cannot open '/home/user/evil.txt' for writing: Permission denied
```

By running the evil script under `sjail`, all writes that are not in the `ALLOWED_FILES` list are not permitted.

#### Restrict Root User

This even includes running `sjail` as the `root` user:

``` shellsession
$ sudo ./sjail . -c /bin/truncate -s 6 ../evil.txt
/bin/truncate: cannot open '../evil.txt' for writing: Permission denied
$ sudo ./sjail . -c /bin/truncate -s 6 /tmp/evil.txt
/bin/truncate: cannot open '/tmp/evil.txt' for writing: Permission denied
$ sudo ./sjail . -c /bin/truncate -s 6 $(echo $HOME)/evil.txt
/bin/truncate: cannot open '/home/user/evil.txt' for writing: Permission denied
```

#### Note about Sudo

However, `sudo` does not work under `sjail` because of `sjail`'s use of `prctl` for restricting privileges:

``` shellsession
$ ./sjail . -c /usr/bin/sudo ./examples/truncate_evil.sh
sudo: The "no new privileges" flag is set, which prevents sudo from running as root.
sudo: If sudo is running in a container, you may need to adjust the container configuration to disable the flag.
```

So, only run `sjail` under `sudo` like the other examples.
