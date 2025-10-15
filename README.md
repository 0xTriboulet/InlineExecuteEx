# InlineExcuteEx
Beacon Object Files (BOFs) in the Cobalt Strike ecosystem are intended to be an abstraction of Position Independent Code (PIC). To maximize
the benefits of this, Cobalt Strike pre-processes BOFs to strip away sections that are not needed to achieve code execution. This design
confers some advantages for users of the framework. It reduces the size of the BOF that Beacon receives from the Teamserver, and the BOF 
loader in Beacon is very small compared to other BOF implementations. Unfortunately, this pre-processing has the inadvertent effect of
reducing the features available from a BOF because the additional information is not available to Beacon at load-time. `InlineExcuteEx`
implements [COFFLoader](https://github.com/trustedsec/COFFLoader) as a Cobalt Strike compatible BOF, which can be used to fire other BOFs
in a more complete way than what is currently possible from Beacon.

## Basic Usage
Load `inline-execute-ex.cna` from the `Script Manager`. This will make the `inline-execute-ex` command available to you.

```
BOF+
====
[EXPERIMENTAL] BOF Loader.

    inline-execute-ex          [EXPERIMENTAL] BOF loader with additional capabilities.
```

You can use the `help inline-execute-ex` command to get some usage information from the command line.

```
beacon> help inline-execute-ex
# 1 - a string containing the BOF file
# 2 - the entry point to call
# 3 - arguments to pass to the BOF file

Usage: inline-execute-ex 'bof.o' 'go' 'hello world!'
```

## Drop-In Replacement for `beacon_inline_execute`
Conventional `.cna` scripts register an alias that calls `beacon_inline_execute` to task Beacon to run a BOF. If you want to use `InlineExecuteEx` instead of the default BOF loader for a capability, you can move the `inline-execute-ex.cna` script, the `Release` directory, and the `x64` directory to the same directory as your BOF's `.cna` script.

```sh
    Directory: C:\CS-Situational-Awareness-BOF\SA


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
[...snip...]
d-----        10/15/2025   4:28 PM                Release
d-----        10/15/2025   4:28 PM                x64
-a----        10/15/2025   4:42 PM           2153 inline-execute-ex.cna
-a----        10/15/2025   4:31 PM          45298 SA.cna
```

Then include the `inline-execute-ex.cna` in your BOF's cna script.
```perl
# SA.cna
include(getFileProper(script_resource("inline-execute-ex.cna"))); # This is the line you want to add

%recordmapping = %(
A => 1,
NS => 2,
MD => 3,
MF => 4,
[...snip...]
```

Lastly, replace calls to `beacon_inline_execute` with `beacon_inline_execute_ex`.
```perl
alias dir {
	local('$params $keys $args $targetdir $subdirs $ttp $text');

[...snip...]

    # We changed the line below
	beacon_inline_execute_ex($1, readbof($1, "dir", $msg, $ttp), "go", $args);
}
```
If all goes well, you should see this when you 
```sh
[10/15 16:36:25] beacon> dir
[10/15 16:36:25] [+] Running dir (T1083)
[10/15 16:36:25] [*] Running dir (T1083)
[10/15 16:36:25] [*] Running InlineExecuteEx.. # <----- It works!
[10/15 16:36:26] [+] host called home, sent: 23152 bytes
[10/15 16:36:26] [+] received output:
Contents of .\*:
	10/15/2025 16:25           <dir> .
	09/07/2025 15:20           <dir> ..
	10/12/2025 12:00          575216 beacon_x64.exe
[...snip...]
	                        66840774 Total File Size for 2 File(s)
	                                                      8 Dir(s)

[10/15 16:36:26] [+] received output:
[+] Success!

```

## Beacon Object File Visual Studio Template

See the [BOF-VS](https://github.com/Cobalt-Strike/bof-vs) repository for more information about the template behind this BOF.