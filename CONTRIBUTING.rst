============
Contributing
============

Issues and Bugs
===============
If you have a bug report or idea for improvement, please create an issue on GitHub, or a pull request with the fix.

Code Reviews
============
All pull requests are subject to professional code review. If you do not want your code reviewed, do not submit it.

Contributors
============

See installation instructions for details on installing boofuzz from source with developer options.

Pull Request Checklist
----------------------

1. Install python version 2.7.9+ **and** 3.6+

2. Verify tests pass:

    .. code-block::

        tox

    .. note::
        (Re-)creating a tox environment on Linux requires root rights because some of your unit tests work with raw
        sockets. tox will check if ``cap_net_admin`` and ``cap_net_raw+eip`` are set on the tox environment python
        interpreter and if not, will do so.

        Once the capabilities have been set, running tox won't need extended permissions.

    .. attention::
        If the tests pass, check the output for new flake8 warnings that indicate PEP8 violations.

3. Format the code to meet our code style requirements (needs python 3.6+):

    .. code-block::

        black .

    Use ``# fmt: off`` and ``# fmt: on`` around a block to disable formatting locally.

4. If you have PyCharm, use it to see if your changes introduce any new static analysis warnings.

5. Modify CHANGELOG.rst to say what you changed.

6. If adding a new module, consider adding it to the Sphinx docs (see ``docs`` folder).

Maintainers
===========

Review Checklist
----------------
On every pull request:

1. Verify changes are sensible and in line with project goals.
2. Verify tests pass (continuous integration is OK for this).
3. Use PyCharm to check static analysis if changes are significant or non-trivial.
4. Verify CHANGELOG.rst is updated.
5. Merge in.


Release Checklist
-----------------
Releases are deployed from GitHub Actions when a new release is created on GitHub.

Prep
++++

1. Create release branch.

2. Increment version number from last release according to PEP 0440 and roughly according to the Semantic Versioning guidelines.

    1. In ``boofuzz/__init__.py``.

    2. In ``docs/conf.py``.

3. Modify CHANGELOG file for publication if needed.

4. Merge release branch.

Release
+++++++

1. Create release on Github.

2. Verify GitHub Actions deployment succeeds.
