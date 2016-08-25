# Openwebvulndb (Tools)

This project consists of a collection of tools to maintain the vulnerability
databases.


## Set-up

General python set-up:

```
virtualenv -ppython3.5 .
source bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

nosetests
```

## Usage

Tools share a common set of libraries when possible, but the entry point is
often project specific due to configuration requirements.

### Common Tools

```
# Find files that appear to be unique or differentiators
python -m openwebvulndb.common find_identity_files -k wordpress
python -m openwebvulndb.common find_identity_files -k plugins/better-wp-security
```

### WordPress Tools

```
# Regenerate the Vane WordPress Scanner vulnerability data
python -m openwebvulndb.wordpress vane_export -i ~/vane/data/

# Re-load CVE data
python -m openwebvulndb.wordpress load_cve

# Obtain the fresh list of plugins and themes
python -m openwebvulndb.wordpress list_plugins
python -m openwebvulndb.wordpress list_themes

# Populate versions (takes a really long time, but you can stop at any point)
#  - Searches through repositories for new versions and populate file hashes
python -m openwebvulndb.wordpress populate_versions
```

# License

Copyright 2016- Delve Labs inc.

This software is published under the GNU General Public License, version 2.
