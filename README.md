# cve_watch

Tracking of patch information base on the CVE number

## Usage

 * Register want to track CVE number

```
$ cve_watch add CVE-2016-5734
```

 * Get a list of the CVE number tracked

```
$ cve_watch list
CVE_NUMBER      CREATED_AT
CVE-2016-4971   2016-08-01 18:58:38
CVE-2016-5734   2016-08-01 18:58:45
```

 * Delete the CVE number

```
$ cve_watch del CVE-2016-4971
```

 * Check the patch has been updated

```
$ cve_watch check
```

## Deploy

```
$ wget https://github.com/KosukeShimofuji/cve_watch/raw/master/release/cve_watch_linux_x64 -O cve_watch
$ chmod 700 cve_watch
```


