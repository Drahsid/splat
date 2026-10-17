from io import StringIO

from ..linker_entry import write_file_if_different


def write_assembly(path, emit, *args):
    with StringIO() as output:
        emit(output, *args)
        write_file_if_different(path, output.getvalue())
