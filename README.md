# inVtero.net
Find/Extract processes, hypervisors (including nested) in memory dumps using microarchitechture independent
Virtual Machiene Introspection techniques

![In Vtero](https://raw.githubusercontent.com/ShaneK2/inVtero.net/gh-pages/images/inVtero.jpg)

## quickdumps
Quickdumps is an example of using the inVtero.net API to extract and validate physical memory.

### Ideal circumstances
The way we initalize our virtual to physical address translation, there are no dependencies on input file format.  Any .DMP,
.RAW, .DD should be fine.  There is a big if unfortunatly.  If the underlying capture format uses some form of extents storage
(i.e. does not consume physical storage for NULL, or NOT PRESENT pages) your milage may vary.  There are lots of tools for
converting memory dumps, volatility - rekal are some good places to start.  BITMAP .DMP files are onthe todo to make analysis
of livedump's easier (currently things work best if you do a manually initiated blue screen with a complete dump configured or
use a 3rd party raw dd type tool).

### Future proof
Several concepts are put to use to ensure we interact with the user only when required.  Similarly to the
[Actaeon](http://www.syssec-project.eu/m/page-media/3/raid13_graziano.pdf) github project @eurecom-s3/actaeon, a primary
goal is to locate and leverage the VMCS page in order to locate the configured EPTP (extended page table pointer) which is
needed to locate the physical pages that belong to a guest OS instance.  Google @google/rekall rekal sunsaquently implmented 
a more expansive implmentation whitch requires the user to run a linux kernel module on the system that a given memory dump
originates that is meant to construct a specialized profile that can be used to then import into a local rekal profile which
will enable you to then isolate/extract guest memory from a physical host dump.

### Easy way
During CanSecWest/DC22 I presented a high quality technique (based on the lowest layer interaction between the CPU and 
OS mm layers) to identify any process running on a system by inspecting physical memory snapshots.  This mechanism is based on
what's called the self pointer (Windows) or recursive page directory pointer (*BSD) that is always expected to be found 
(unless your Windows system has a hevially modified/patched mm, or simply a custom kernel for *BSD).  The net result of this
is that we know all given CR3 register values.  Since the VMCS contains at least 1 known CR3 value (a second one may be 
emulated or dynamically remapped) we have confidence that a comprehensive memory dump can be performed with out knowing anything
about the underlying OS version (e.g. XP(64bit)->Win2016 are consistant) or microarchitechture.

### Speed 
Brute force always win's at the end of the day!  Or so I hear...  In any case, if an unknown VMCS mapping is found (EPTP index),
quickdumps will emite a set of possiable values/indexes.  The list is usually small, 10-20 at the most.  An upcoming feature
is to automate attempts for each possiable value until one that 'works' is found.  This should ensure we work for upcoming 
CPU microarchitechtures without any code changes (or I will likely setup some class's that specify these to make life easy).
Either way, brute forcing should be fairly quick.  I try to make the most of multi-core CPU's, so if you have extra cores, 
they will likely get a workout if your analyzing a huge dump with many VM's.

Example run from a laptop:
```

Hypervisor: VMCS revision field: VMWARE_NESTED [00000001] abort indicator: NO_ABORT [00000000]
Hypervisor: Windows CR3 found = [00000000001AB000)] byte-swapped: [00B01A0000000000] @ PAGE/File Offset = [0000000195923000]
Dumping possiable physical Block Values.  [Offset-decimal][Value-hex]

[3][00000000986E2000] [14][000000007433301E] [277][0000000080050033] [278][00000000001AB000] [279][00000000000526F8]
[284][000000007F5F5000] [323][000000008005003B] [324][0000000074C00248] [325][00000000000626E0] [372][000000000033EFFB]
[415][00000000FFFFFFFF]

Hypervisor: VMCS revision field: VMWARE_NESTED [00000001] abort indicator: NO_ABORT [00000000]
Hypervisor: Windows CR3 found = [00000000001AB000)] byte-swapped: [00B01A0000000000] @ PAGE/File Offset = [00000001959A4000]
Dumping possiable physical Block Values.  [Offset-decimal][Value-hex]

[3][00000000986E2000] [14][000000007433301E] [277][0000000080050033] [278][00000000001AB000] [279][00000000000526F8]
[284][000000007F610000] [323][000000008005003B] [324][0000000074C00258] [325][00000000000626E0] [372][000000000033EFFB]
[415][00000000FFFFFFFF]

10 candiate VMCS pages. Time to process: 00:03:43.1639847
Data scanned: 34,171,150,654.00 rate: 1,515.000 MB/s
```

In the above example, VMWARE's EPTP is at index 14 in it's VMCS.

### Bugs :(
~~* We'll see if I get this one knocked out but right now it's only dumping kernel memory from each layer.  Working on user-space
        from guest OS VM's.~~ 
* Lots of TODO's but I'm going to add as soon as possiable.  The main issue right now is that I'm really hestitant to add anything
   that's OS supplied even if it'd be a huge help.  I think sufficent context is available to avoid adding any logical OS dependencies.
   I like how Rekal pledges this but it seems their profile archive is very large also, so a bit of both.  
   There's a bit of cleanup to do still. This is still alpha, but will be activly developing.

* Expand to more known EPTP types so no brute force required
    * Brute force only takes a minute or so though... ;)
* Going to create a PFN bitmap index to auto-magically determine run's (currently, if your trying to dump/query anything after a run,
   it will cause problems or be missed etc.  Will be adding this next to ensure we get 100% comprehensive dumps.

## Goals
To refrain from using OS logical structures to support memory analysis.  It's likely that most OS layer structures, data,
code and objects may be manipulated by an attacker to misdirect an analyist's efforts.






[Documentation](http://ShaneK2.github.io/inVtero.net)  
[GUI Implmentation](https://blockwatch.ioactive.com/)
