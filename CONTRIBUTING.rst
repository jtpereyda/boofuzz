Issues and Bugs
===============
If you have a bug report or idea for improvement, please create an issue on GitHub, or a pull request with the fix.

Code Reviews
============
All pull requests are subject to professional code review. If you do not want your code reviewed, do not submit it.

Contributors
============

Pull Request Checklist
----------------------

1. Verify tests pass:
  ::

      tox

2. If you have PyCharm, use it to see if your changes introduce any new static analysis warnings.

3. Modify CHANGELOG.rst to say what you changed.

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

Prep
++++

1. Create release branch.

2. Use :code:`git status` to verify that no superfluous files are present to be included in the source distribution.

3. Increment version number from last release according to PEP 0440 and roughly according to the Semantic Versioning guidelines.

4. Modify CHANGELOG file:

  - Update version number.
  - Edit release notes for publication.

5. Verify tests pass (continuous integration is OK for this).

6. Merge release branch.

Checks
++++++

1. Use :code:`git status` to verify that no superfluous files are present to be included in the source distribution.

2. Build distributions:
  ::

      python setup.py sdist bdist_wheel

3. Visually inspect wheel distribution for correctness.

Release
+++++++

1. Upload to testpypi if changes impact PyPI (e.g., if README changed):
  ::

      twine upload -r test  dist\ezoutlet-x.y.z-py2-none-any.whl dist\ezoutlet-0.0.1-dev3.zip


2. Upload to pypi:
  ::

      twine upload dist\ezoutlet-x.y.z-py2-none-any.whl dist\ezoutlet-0.0.1-dev3.zip

.. _check-manifest: https://pypi.python.org/pypi/check-manifest

3. Create accompanying release on GitHub.
