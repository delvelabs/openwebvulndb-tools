from argparse import ArgumentParser

from openwebvulndb import app


def find_identity_files(storage, input_key):
    versions = storage.read_versions(input_key)

    from collections import defaultdict
    file_map = defaultdict(list)
    for v in versions.versions:
        for s in v.signatures:
            file_map[s.path].append(s.hash)

    data = [(len(set(values)), len(values), path) for path, values in file_map.items()]
    data.sort(reverse=True)
    for uniques, total, path in data:
        print("%s/%s    %s" % (uniques, total, path))

    print("Total version count: %s" % len(versions.versions))


operations = dict(find_identity_files=find_identity_files)


parser = ArgumentParser(description="OpenWebVulnDb Data Collector")
parser.add_argument("action", choices=operations.keys())
parser.add_argument('-k', '--key', dest='input_key', default="wordpress",
                    help='Software key for targetting specific plugins or themes')
args = parser.parse_args()


try:
    local = app.sub(input_key=args.input_key)
    local.call(operations[args.action])
except KeyboardInterrupt:
    pass
finally:
    app.close()
