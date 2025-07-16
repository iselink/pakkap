# Pakkap

Captures packets on the interface (like tcpdump) with the following criteria:

- Split into multiple files over time
- Check if there is enough space on the filesystem (still can go a little bit over)

And later maybe do other stuff like:

- Upload files into S3 storage
- Other forms of processing

The existence of this tool is dictated by mine (and likely company needs) and mine decision to write just golang binary
blob.  
Instead of tcpdump, df and some bash scripting...

For compiling, you need to have `libpcap-dev` (`apt install libpcap-dev`).

This program is quick-and-dirty written — I just bashed my head into keyboard, and it is doing what I need rn.

------

List of return codes:

| Code | Meaning                                 | 
|------|-----------------------------------------|
| 0    | Successful exit                         |
| 1    | Unknown (general) error                 |
| 2    | Invalid flag value                      |
| 3    | Runtime error (insufficient disk space) |