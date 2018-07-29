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

1. Verify tests pass: ::

      tox

2. If you have PyCharm, use it to see if your changes introduce any new static analysis warnings.

3. Modify CHANGELOG.rst to say what you changed.

4. If adding a new module, consider adding it to the Sphinx docs (see ``docs`` folder).

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
Releases are deployed from Travis based on git tags.

Prep
++++

1. Create release branch.

2. Increment version number from last release according to PEP 0440 and roughly according to the Semantic Versioning guidelines.

3. Modify CHANGELOG file for publication if needed.

4. Merge release branch.

Release
+++++++

1. Create release tag in Github.

2. Verify Travis deployment succeeds.
