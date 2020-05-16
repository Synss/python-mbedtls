import sys
from io import StringIO

import pytest

try:
    from pathlib import Path
except ImportError:
    from pathlib2 import Path


if sys.version_info < (3, 9):
    from readme_renderer.rst import render
else:
    render = None


@pytest.mark.skipif(render is None, reason="html5lib issue #419")
def test_pypi_rendering():
    # Adapted from `https://stackoverflow.com/questions/46766570/`.
    readme = Path("README.rst")
    warnings = StringIO()
    with readme.open() as file_:
        html = render(file_.read(), stream=warnings)
        warnings.seek(0)
        assert html is not None, warnings.read()
