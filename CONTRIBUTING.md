
# Contributing to `python-mbedtls`

## Code of conduct

Simply be a nice person in all communications.


## Coding guidelines

### Coding style

Both Cython and Python code must follow the [PEP 8 -- Style guide for
Python code](https://www.python.org/dev/peps/pep-0008/).  This includes
the tests.  Although [black](https://github.com/ambv/black) does not yet
support Cython, new code should resemble its output.

### Tests

`python-mbedtls` uses [pytest](https://docs.pytest.org/en/latest/) and
makes extensive use of fixtures.  New tests should follow the already
existing style.

In general, every new method must be called at least once by a test and
these tests must be short.
[Parametrize](https://docs.pytest.org/en/latest/parametrize.html) tests
and fixtures to check edge cases, etc.

Demonstrate common use cases with extra tests for new features.

Also see [tests/test_hkdf.py](tests/test_hkdf.py) for examples
of test vectors.

*NOTE: PRs without tests will no be merged!*

### Documentation

Document every new class and public method using [Google-style
docstrings](https://sphinxcontrib-napoleon.readthedocs.io/en/latest/).
Adapting the documentation from `libmbedtls` is acceptable in most
cases.  See also [PEP 257 -- Docstring
Conventions](https://www.python.org/dev/peps/pep-0257/).

For new features, an example usage should be added to the README.

Finally, you should summarize your contribution with a one-liner in the
ChangeLog.  Have your name or handle here as well.

## Commit guidelines

`python-mbedtls` follows a linear workflow where every feature is
fast-forward merged onto the master branch.

The rule for the size of a commit is one feature per commit and one
commit per feature.  In particular, do not mix bug fixes and new
features in one commit but open several pull requests instead.

The commit messages start with the file/feature modified or added,
followed by colon and a space, followed by a short title.  This first
line should not exceed 50 characters.  It may be followed by an empty
line and a long description.  Lines on the long description should fit
within 72 characters and markdown formatting is allowed.

See also:
 * [Pro Git](https://git-scm.com/book/en/v2).
 * `git log` for examples.
