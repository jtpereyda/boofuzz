boofuzz
=======
boofuzz is a fork of and the successor to the [Sulley](https://github.com/OpenRCE/sulley) fuzzing framework.
Besides numerous bug fixes, boofuzz aims for extensibility, with the eventual goal of being able to fuzz literally anything.

Why?
----
Sulley has been the preeminent open source fuzzer for sometime, but has fallen out of maintenance.

Features
--------
Like Sulley, boofuzz seeks to incorporate all the critical elements of a fuzzer:
 - easy and quick data generation
 - instrumentation, AKA failure detection
 - target reset after failure
 - recording of test data

Unlike Sulley, boofuzz also features:
 - support for arbitrary communications mediums
 - _extensible_ instrumentation/failure detection
 - better recording of test data
 
Sulley is affectionately named after the creature from Monsters Inc., because of his fuzziness.
Boofuzz is likewise named after the only creature known to have given Sulley himself a fright, boo!

![Boo from Monsters Inc](http://s21.postimg.org/rssnxdho7/boo_happy.png)

Installation
------------
boofuzz has inherited Sulley's glories... and blemishes. The install process might be a bear, but if you come out the other side, you will have the world's foremost fuzzing framework finally at your fingertips!

See [Sulley's Windows installation guide](https://github.com/OpenRCE/sulley/wiki/Windows-Installation).
Unix users can also use the article as a guideline.

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
