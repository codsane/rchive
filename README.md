# rchive
A python script to archive your reddit saved/upvoted posts

## Getting Started
```
git clone https://github.com/codsane/rchive.git
```

### Config File
To be used with configparser. Defaults to config.ini

Example:

```
[rchive]
client_id = 
client_secret = 
username = 
password = 
user_agent = 

database =
```
For reddit credentials, see: [PRAW Docs - Auth. - Password Flow](https://praw.readthedocs.io/en/latest/getting_started/authentication.html#password-flow).

For user agent, typically "*/u/username's PRAW Client*" is sufficient.

For database connection, see: [dataset docs](https://dataset.readthedocs.io/en/latest/quickstart.html#connecting-to-a-database).


## Usage
`python rchive.py [OPTIONS]`

| option (short) | option (long)             | description                                                                       |
|----------------|---------------------------|-----------------------------------------------------------------------------------|
|  `-c`          | `--config`                  | Config file to be loaded (default: `config.ini`)                                                          |        
|  `-v`          | `--verbose`          | Set logging level to DEBUG                                     |
|  `-e`          | `--export`           | rchive by default only preserves self posts and comments. In order to archive full URLs and media, you can export the URLs from your rchive database and send them to something like [ArchiveBox](https://github.com/pirate/ArchiveBox), [Shaarli](https://github.com/sebsauvage/Shaarli), etc.                                                 |
|  `-f`	   | `--format FORMAT`	| Format to export URLs to (formats: `text/txt`)							               |
|            | `--skip-archive`	                 | Skip archive (use with --export to export database without connecting to PRAW)                               |
|            | `--include-comment-urls`	                 | Also include URLs which have been regex\'d out of comments (use with --export)                               |
|            | `--include-selftext-urls`	                 | Also include URLs which have been regex\'d out of selftext posts (use with --export)                               |
|            | `--use-new-reddit`	                 | Use new reddit to generate permalinks                               |