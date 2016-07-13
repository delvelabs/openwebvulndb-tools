from os.path import join, dirname


def read_file(relative, file):
    full_path = join(dirname(relative), file)
    with open(full_path, 'r') as fp:
        return fp.read()
