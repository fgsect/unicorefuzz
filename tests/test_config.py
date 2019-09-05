from typing import Callable
from unicorefuzz import configspec


def test_config_load():
    config = configspec.load_config("../example_module/config.py")
    assert hasattr(config, "AFL_INPUTS")


def test_config_print():
    print(configspec.serialize_spec(configspec.UNICOREFUZZ_SPEC))


def test_is_callable_type():
    assert configspec.is_callable_type(Callable[[int], None])
    assert configspec.is_callable_type(Callable)
    assert configspec.is_callable_type(callable)
    assert not configspec.is_callable_type(str)
    assert not configspec.is_callable_type(lambda x: None)
