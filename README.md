# InlineExcuteEx
Beacon Object Files (BOFs) in the Cobalt Strike ecosystem are intended to be an abstraction of Position Independent Code (PIC). To maximize
the benefits of this, Cobalt Strike pre-processes BOFs to strip away sections that are not needed to achieve code execution. In addition
to reducing the size of the BOF, the BOF loader in Beacon is very small compared to other BOF implementations. Unfortunately, this pre-processing
has the inadvertent effect of reducing the features available from a BOF because the additional information is not available to Beacon
at load-time. `InlineExcuteEx` implements [COFFLoader](https://github.com/trustedsec/COFFLoader) as a Cobalt Strike compatible BOF, which
can be used to fire other BOFs.

## Usage
Load `inline-execute-ex.cna` from the `Script Manager`, this will make the `inline-execute-ex` command available to you.

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

## Beacon Object File Visual Studio Template

[This repository](https://github.com/Cobalt-Strike/bof-vs) contains the Beacon Object File Visual Studio (BOF-VS) template project.
You can read more about rationale and design decisions from this blog [post](https://www.cobaltstrike.com/blog/simplifying-bof-development).

## Quick Start Guide

To get started, use the instructions provided below.

### Video Walkthrough

<center><video width="720" heigth="480" crossorigin="anonymous" aria-label="BOF-VS setup" x-webkit-airplay="allow" playsinline="" controls controlslist="nodownload"><source src="https://raw.githubusercontent.com/Cobalt-Strike/bof-vs/main/media/Setup%20BOF-VS.mp4" type="video/mp4"></video></center>
   
https://github.com/user-attachments/assets/256fec31-bf25-4c10-9a10-0ab50751ca6d

See the [BOF-VS](https://github.com/Cobalt-Strike/bof-vs) repository for more information about the template behind this BOF.