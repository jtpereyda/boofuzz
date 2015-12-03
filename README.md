boofuzz
=======
Boofuzz is a fork of and the successor to the [Sulley](https://github.com/OpenRCE/sulley) fuzzing framework.
Besides numerous bug fixes, boofuzz aims for extensibility, with the eventual goal of being able to fuzz literally anything.

Why?
----
Sulley has been the preeminent open source fuzzer for sometime, but has fallen out of maintenance.

Features
--------
Like Sulley, boofuzz incorporates all the critical elements of a fuzzer:

 - Easy and quick data generation.
 - Instrumentation, AKA failure detection.
 - Target reset after failure.
 - Recording of test data.

Unlike Sulley, boofuzz also features:

 - Much easier install experience!
 - Support for arbitrary communications mediums.
 - _Extensible_ instrumentation/failure detection.
 - Better recording of test data.
 - Far fewer bugs.
 
Sulley is affectionately named after the creature from Monsters Inc., because of his fuzziness.
Boofuzz is likewise named after the only creature known to have scared Sulley himself, boo!

![Boo from Monsters Inc](http://s21.postimg.org/rssnxdho7/boo_happy.png)

Installation
------------
Boofuzz installs as a Python library used to build fuzzer scripts.
See [INSTALL.md]() for step-by-step instructions.

Getting Started
---------------
No quickstart guide is available yet, but in the mean time you can use this [Sulley FTP example](https://www.securepla.net/fuzzing-101-with-sulley/) as a baseline.

Contributions
-------------
Pull requests are welcome, as boofuz is actively maintained (at the time of this writing ;)).

Support
-------
If your question takes the form of "How do I... with boofuzz?" or "I got this error with boofuzz, why?", consider posting your question on Stack Overflow. Make sure to use the `fuzzing` tag.

If you've found a bug, or have an idea/suggestion/request, file an issue here on GitHub.

For other questions, feel free to [email me](https://github.com/jtpereyda).
