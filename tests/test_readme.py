# SPDX-License-Identifier: MIT

from __future__ import annotations

import sys
from io import StringIO
from pathlib import Path

import pytest

if sys.version_info < (3, 9):
    from readme_renderer.rst import render
else:
    render = None


@pytest.mark.skipif(render is None, reason="html5lib issue #419")
def test_pypi_rendering() -> None:
    # Adapted from `https://stackoverflow.com/questions/46766570/`.
    readme = Path(__file__).parent.parent / "README.rst"
    warnings = StringIO()
    with readme.open() as file_:
        assert render is not None
        html = render(file_.read(), stream=warnings)
        warnings.seek(0)
        assert html is not None, warnings.read()
