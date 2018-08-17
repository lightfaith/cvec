# cvec
Collection of  to compare list of packages against known vulnerabilities and exploits.

### Usage:

```sh
  ./update_db.py
  dpkg -l | ./check_packages.py --exploit | less -R
```
