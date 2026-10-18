import sslcontext


def test_version_comes_from_installed_metadata():
    assert sslcontext.__version__ != "0+unknown"
