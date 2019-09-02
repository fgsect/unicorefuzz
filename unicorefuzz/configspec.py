import collections
import inspect
import os
from typing import (
    List,
    Union,
    Any,
    Dict,
    Callable,
    TypeVar,
)  # other types are not supported, sorry...

from unicorefuzz import unicorefuzz
from unicorn import unicorn

Required = collections.namedtuple("Required", "key type description param_names")
Required.__new__.__defaults__ = ("*args",)
Optional = collections.namedtuple(
    "Optional", "key type default description param_names"
)
Optional.__new__.__defaults__ = ("*args",)

DEFAULT_PAGE_SIZE = 0x1000


def nop_func(*args, **kwargs):
    pass


# The spec the config.py needs to abide by.
UNICOREFUZZ_SPEC = [
    Required("ARCH", list(unicorefuzz.archs.keys()), "What architecture to emulate"),
    Optional(
        "PAGE_SIZE",
        int,
        DEFAULT_PAGE_SIZE,
        "The page size used when fetching and mapping memory",
    ),
    Required(
        "SCRATCH_ADDR", int, "Location of free Scratch Memory, not used by the target"
    ),
    Optional(
        "SCRATCH_SIZE",
        int,
        lambda config: config.PAGE_SIZE,
        "Size of the mapped scratch memory",
    ),
    Optional("GDB_HOST", str, "localhost", "The GDB Host to connect to"),
    Required("GDB_PORT", int, "The GDB port to connect to"),
    Optional("BREAKADDR", Union[int, None], None, "The absolute address to break at"),
    Optional(
        "MODULE",
        Union[str, None],
        None,
        "A linux kernel module to break in (cannot be combined with BREAKADDR)",
    ),
    Optional(
        "BREAKOFFSET",
        Union[int, None],
        None,
        "Relative location in the MODULE to break in",
    ),
    Optional(
        "EXITS", List[int], [], "Absolute addresses at which Ucf should stop fuzzing"
    ),
    Optional(
        "ENTRY_RELATIVE_EXITS",
        List[int],
        [],
        "EXITS relative to initial PC at uc.emu_start (entrypoint + addr)",
    ),
    Optional(
        "WORKDIR",
        str,
        os.path.join(os.getcwd(), "unicore_workdir"),
        "Path to UCF workdir to store state etc.",
    ),
    Optional(
        "UNICORE_PATH",
        str,
        os.path.dirname(os.path.abspath(__file__)),
        "Custom path of Unicore installation",
    ),
    Required("AFL_INPUT", str, "The seed directory to use for fuzzing"),
    Optional(
        "AFL_OUTPUT",
        Union[str, None],
        lambda config: os.path.join(config.UNICORE_PATH, "afl_output"),
        "AFL output directory to use for fuzzing (default will be inside WORKDIR)",
    ),
    Optional("AFL_DICT", Union[str, None], None, "AFL dictionary to use for fuzzing"),
    Optional(
        "init_func",
        Callable[[unicorefuzz.Unicorefuzz, unicorn.Uc], None],
        lambda config: nop_func,
        """An init function called before forking.
        Will receive handle to ucf and unicorn as parameters.
        This function may be used to set additional unicorn hooks and things.
        Use ucf.map_page(addr) if you need to access/alter memory that may not be available.
        Set the program counter here if you want to fuzz somewhere else.
        If you uc.run_emu here, you will start the forkserver! Try not to/do that in place_input. :)
        Does not return anything.
        :param ucf: unicorefuzz instance
        :param uc: fully initialized unicorn instance""",
        "ucf, uc",
    ),
    Required(
        "place_input",
        Callable[[unicorefuzz.Unicorefuzz, unicorn.Uc, bytes], None],
        """Function placing input to the unicorn state. It receives ucf, unicorn and input as parameters.
        The function will be called for each execution, so keep it lightweight.
        Think testcase in libfuzzer.
        If you want to ignore an input, you can ucf.exit(exitcode) here.
        This will call through to os._exit(0). Anything else is a lot slower.
        :param ucf: unicorefuzz instance
        :param uc: fully initialized unicorn instance
        :param input: the input""",
        "ucf, uc, input",
    ),
]  # type: List[Union[Required, Optional]]


def is_callable_type(typevar):
    """
    Returns True if typevar is callable or Callable
    """
    if typevar == callable or typevar == Callable:
        return True
    # This return is split in 2 parts to calm down pycharms static analyzer.
    if hasattr(typevar, "__origin__"):
        # noinspection PyUnresolvedReferences
        return typevar.__origin__ == Callable.__origin__
    return False


def clean_source(func):
    source = inspect.getsource(func).split(":", 1)[1].strip()
    if source.endswith(","):
        # special case for lambdas
        return source[:-1]
    return source


def stringify_spec_entry(entry):
    # type: (Union[Optional, Required]) -> str
    """Make a nice string out of it."""
    entrytype = entry.type
    if isinstance(entrytype, type):
        entrytype = entrytype.__name__
    # ugly hack: We don't want a list to be ['like', 'this'] but ["with", "json", "quotes"]...
    entrytype = "{}".format(entrytype).replace("'", '"')
    if isinstance(entry, Required):
        if is_callable_type(entry.type):
            return '''def {}({}):
    #  type: {}
    """
    {}
    """
    TODO
    '''.format(
                entry.key, entry.param_names, entrytype, entry.description
            )
        return '"""{}"""\n{} = TODO #  type {}'.format(
            entry.description, entry.key, entrytype
        )
    if isinstance(entry, Optional):
        # If it's a func, we only want the print the content.
        default = entry.default
        if callable(entry.default):
            default = clean_source(default)
        if is_callable_type(entry.type):
            default = clean_source(eval(default))
            return '''def {}({}):
    #  type: {}
    """[Optional]
    {}
    """
    {}
    '''.format(
                entry.key, entry.param_names, entrytype, entry.description, default
            )
        return '"""[Optional] {}"""\n{} = {} #  type {}'.format(
            entry.description, entry.key, default, entrytype
        )
    raise ValueError(
        "Could not stringify unknown entry type {}: {}".format(type(entry), entry)
    )


def serialize_spec(spec):
    # type: (List[Union[Optional, Required]]) -> str
    """
    Prints a checker json spec in a readable multiline format
    :param spec: a spec
    :return: formatted string
    """
    return "\n\n".join(
        [
            "# Config options for unicorefuzz\n"
            "# Values tagged as [Optional] are autofilled by ucf if not set explicitly."
        ]
        + [stringify_spec_entry(x) for x in spec]
    )


def type_matches(val, expected_type):
    """
    Returns if the type equals the expectation
    :param val: The value
    :param expected_type: The type or a list of allowed values
    :return: True if the type is correct, False otherwise
    """
    if isinstance(expected_type, list):
        # A list of allowed values is given, not an actual type
        return val in expected_type
    elif expected_type == Any:
        return True
    elif expected_type is None:
        return val is None
    elif hasattr(expected_type, "__origin__"):
        # Something from the typing module
        if expected_type.__origin__ == Union:
            for union_member in expected_type.__args__:
                if type_matches(val, union_member):
                    return True
        elif is_callable_type(expected_type):
            return callable(val)
        elif expected_type.__origin__ == dict:
            if not isinstance(val, dict):
                return False
            for key in val.keys():
                if not type_matches(key, expected_type.__args__[0]):
                    return False
            for value in val.values():
                if not type_matches(key, expected_type.__args__[1]):
                    return False
            return True
        elif expected_type.__origin__ == list:
            if not isinstance(val, list):
                return False
            for el in val:
                if not type_matches(el, expected_type.__args__[0]):
                    return False
            return True
    elif isinstance(expected_type, TypeVar):
        # too complex to check if TypeVars (List[TypeVar]) are alright... Treat like Any
        return True
    elif isinstance(val, expected_type):
        return True
    return False


def check_type(name, val, expected_type):
    # type: (str, str, Any) -> None
    """
    returns and converts if necessary
    :param name: the name of the value
    :param val: the value to check
    :param expected_type: the expected type
    """
    if not type_matches(val, expected_type):
        raise ValueError(
            "{} should be '{}' but is {} of type '{}'.".format(
                name, expected_type.__name__, val, type(val).__name__
            )
        )


def import_py(mod_name, mod_path):
    """
    Imports a python module by path
    :param mod_name: the name the module should be imported by
    :param mod_path: the path to load the module from
    :return: the module, as reference
    """
    # see https://stackoverflow.com/questions/67631/how-to-import-a-module-given-the-full-path
    if not os.path.isfile(mod_path):
        raise IOError(
            "Could not open config at {} as file.".format(os.path.abspath(mod_path))
        )
    else:
        print("[+] Reading config from {}".format(os.path.abspath(mod_path)))
    try:
        # python3.5+
        import importlib.util

        spec = importlib.util.spec_from_file_location(mod_name, mod_path)
        if not spec:
            raise EnvironmentError(
                "Could not load {} from {}".format(mod_name, mod_path)
            )
        mod = importlib.util.module_from_spec(spec)
        return unicorefuzz.__loader__.exec_module(mod)
    except EnvironmentError:
        raise
    except:
        pass  # we are not python 3.7, apparently.
    try:
        # python2.7 (untested)
        import imp

        return imp.load_source(mod_name, os.path.abspath(mod_path))
    except Exception as ex:
        print(ex)
    try:
        # python 3.3-3.4 (untested)
        from importlib.machinery import SourceFileLoader

        return SourceFileLoader(mod_name, mod_path).load_module()
    except Exception as ex:
        print(ex)
        raise EnvironmentError("Could not load {} from {}".format(mod_name, mod_path))


def load_config(path):
    """
    :param path: path to config.py (including filename)
    :return: Loaded config (or ValueError)
    """
    path = os.path.abspath(path)
    config = import_py("unicoreconfig", path)
    apply_spec(config, UNICOREFUZZ_SPEC)
    return config


def apply_spec(module, spec, print_info=True):
    # type: (Module, List[Union[Optional, Required]], bool) -> None
    """
    Checks if config implements the spec or parts are missing.
    Fills in Optional() values with their respective default values.
    If Optional defaults are callable, they will be called with the current module as parameter.
    The spec is iterated in order - make sure optional values only depends on previous values.

    In case the spec fails, errors out with ValueError.
    :param json:  the json
    :param spec: the spec
    :param print_info: print info about replaced defaults.
    """
    errors = []
    if print_info:
        def print_maybe(*args):
            print(*args)

    else:
        def print_maybe(*args):
            pass

    for entry in spec:
        if not hasattr(module, entry.key):
            # Entry not found.
            if isinstance(entry, Optional):
                default = entry.default
                if callable(default):
                    default = entry.default(module)
                print_maybe(
                    "[*] Optional setting {} not set. Using default value: {}.\n\tDescription: {}".format(
                        entry.key, default, entry.description
                    )
                )
                setattr(module, entry.key, default)
            else:
                print_maybe(
                    "[-] Error: Required option {} not set! Please add it to config.py.\n\tDescription: {}".format(
                        entry.key, entry.description
                    )
                )
                errors.append(entry)
        else:
            # Value found. Check.
            val = getattr(module, entry.key)
            try:
                check_type(entry.key, val, entry.type)
            except ValueError as ex:
                print_maybe(
                    "[-] Error: Required option {} has wrong type! {}\nPlease fix in config.py.\n\tDescription: {}".format(
                        entry.key, ex, entry.description
                    )
                )
                errors.append(entry)
    if errors:
        raise ValueError(
            "Could not load required values from config.py: \n{}".format(
                "\n".join([stringify_spec_entry(x) for x in errors])
            )
        )
