from io import StringIO

try:
    from pathlib import Path
except ImportError:
    from pathlib2 import Path
from readme_renderer.rst import render


def test_pypi_rendering():
    # Adapted from `https://stackoverflow.com/questions/46766570/`.
    readme = Path("README.rst")
    warnings = StringIO()
    with readme.open() as file_:
        html = render(file_.read(), stream=warnings)
        warnings.seek(0)
        assert html is not None, warnings.read()
