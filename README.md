# Openwebvulndb (Tools)

This project consists of a collection of tools to maintain the vulnerability
databases.


## Set-up

General python set-up:

```
virtualenv -ppython3.8 .
source bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

nosetests
```

External requirements set-up:

```
sudo apt-get install subversion
```

## Usage

Tools share a common set of libraries when possible, but the entry point is
often project specific due to configuration requirements.

### Common Tools

```
# Find files that appear to be unique or differentiators
python -m openwebvulndb.common find_identity_files -k wordpress
python -m openwebvulndb.common find_identity_files -k plugins/better-wp-security

# List vulnerabilities with no known fixed_in
python -m openwebvulndb.common find_unclosed_vulnerabilities
python -m openwebvulndb.common find_unclosed_vulnerabilities --filter popular
```

### WordPress Tools

```
# Regenerate the Vane WordPress Scanner vulnerability data
python -m openwebvulndb.wordpress vane_export -i ~/vane/data/

# Export the Vane 2.0 WordPress Scanner vulnerability data.
# Add Vane 2 data as an asset of a release on the GitHub repository configured in the virtual environment.
# The environment variables required are:
#   - VANE2_REPO_NAME=name-of-the-repository
#   - VANE2_REPO_OWNER=github-username
#   - VANE2_REPO_PASSWORD=password-or-personal-access-token
# With no argument, the data will be added to the latest release. To create a new release for the data,
# use the --create-release option. The current date will be used for the release number. A custom version number can
# be specified with --release-version
# --target-commitish can be ignored for now, as the default is master.
python -m openwebvulndb.wordpress vane2_export [--create-release] [--target-commitish branch|commit] [--release-version]

# Re-load CVE data
python -m openwebvulndb.wordpress load_cve

# Obtain the fresh list of plugins and themes
python -m openwebvulndb.wordpress list_plugins
python -m openwebvulndb.wordpress list_themes

# Populate versions (takes a really long time, but you can stop at any point)
# Searches through repositories updated in the last 30 days and populate versions file hashes.
# --interval is used to change the default value of 30 days. -w or --wp-only only update WordPress core versions.
python -m openwebvulndb.wordpress populate_versions [--interval days] [-w | --wp-only]

# Fetch the latest vulnerabilities about WordPress on Security Focus and update the vulnerability database.
python -m openwebvulndb.wordpress update_securityfocus_database
```

# License

Copyright 2016- Delve Labs inc.

This software is published under the GNU General Public License, version 2.
