# Upcoming changes
Feel free to drop some suggestions and I'll see what I can build in.  Anything from GUI's to .NET CORE versions.

## TODO
To solve any memory gap issues while maintaining a minimal interaction with OS suppled inputs, I'm not going to be
importing the PFN database from the typically fairly consistant regions.  Instead I'm going to be opt towards a series
of page table walks that will populate an embedded RaptorDB (performed fairly well with even a Billion inserts). This should
provide a comprehensive mapping even if it may require more than 2 passes.  Trying to keep things space efficent w/o blowing
too much CPU. :)

## Format awareness
New formats made this is to enhance usefullness. Will be finalinzing generic PFN/RUN extraction eventually but practically 
being more usefull sooner is nice.

## Upcoming Changes
~~* Improved memory map windowing~~
~~* Process/GM grouping~~


### Soonish, see @Reloc
* Delocation -- match disk hashes to what comes out of memory
