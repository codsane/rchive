from datetime import datetime
from loguru import logger
import configparser
import argparse
import dataset
import praw
import sys
import os
import re

# ArgumentParser Setup
parser = argparse.ArgumentParser()
# Todo – Clean up these arguments with subparsers
parser.add_argument('--config', default='config.ini', help='Config file to be loaded (default = "config.ini")')
parser.add_argument('-v', '--verbose', help='Set the console logger level to DEBUG', action='store_true')
parser.add_argument('--skip-archive', help='Skip archive - Use with --export to export database without archiving new saved/upvoted (won\'t connect to PRAW)', action='store_true')
parser.add_argument('--export', help='rchive by default only preserves self posts and comments. In order to archive full URLs and media, you can export the URLs from your rchive database and send them to something like ArchiveBox, Shaarli, etc.', action='store_true')
parser.add_argument('--format', help='Format to export URLs to (json, text) (Used in conjunction with --export)')
parser.add_argument('--include-comment-urls', help='Also include URLs which have been regex\'d out of comments (Optionally used in conjunction with --export)', action='store_true')
parser.add_argument('--include-selftext-urls', help='Also include URLs which have been regex\'d out of selftext posts (Optionally used in conjunction with --export)', action='store_true')
parser.add_argument('--use-new-reddit', help='Use new reddit to generate permalinks', action='store_true')
args = parser.parse_args()

# Logging Setup
logger.remove()
if args.verbose:
	logger.add(sys.stderr, level="DEBUG")
else:
	logger.add(sys.stderr, level="INFO")
logger.add("rchive.log", level="DEBUG", rotation="5 MB") # File is always set to debug, 5MB rotation because he's a big boi


class rchive:

	def __init__(self, config):
		logger.debug('Using config file {}'.format(config))
		cp = configparser.ConfigParser()
		cp.read(config)

		self.reddit = self.login(cp)
		self.db = self.get_database(cp)

	def archive_all(self):
		"""Runs a full export of saved and upvoted submissions"""
		self.archive_saved(rate_limit=None)
		self.archive_upvoted(rate_limit=None)
		# Todo - archive functions for submissions/comments, probably from PushShift so that timesearch can take care of the rest

	def login(self, config):
		"""Auth with Reddit via PRAW"""
		client_id = config.get("rchive", "client_id")
		client_secret = config.get("rchive", "client_secret")
		username = config.get("rchive", "username")
		password = config.get("rchive", "password")
		user_agent = config.get("rchive", "user_agent")

		try:
			reddit = praw.Reddit(client_id=client_id,
								 client_secret=client_secret,
								 user_agent=user_agent,
								 username=username,
								 password=password)

			logger.success('Logged in as: {}'.format(reddit.user.me()))
		except Exception as e:
			logger.exception(e)

		return reddit

	def get_database(self, config):
		"""Returns a dataset db object for use with rchive"""
		# First check to see if theres a db url in the config
		if config.has_option('rchive', 'database'):
			url = config.get('rchive', 'database')
		else:
			# Build the database URL for a SQLite database using the reddit users name
			username = str(self.reddit.user.me())
			url = 'sqlite:///{}.db'.format(username)
		logger.debug('Attempting to use db url {}'.format(url))
		return dataset.connect(url)

	def process_submissions(self, submissions, origin):
		"""Processes PRAW:Submissions (comments and posts) into the database"""
		logger.info('Processing {} items...'.format(origin))
		posts = self.db['posts']
		comments = self.db['comments']
		origin_log = self.db[origin]
		count = 0 # Count number of submissioons
		new_count = 0 # Count number of new db entries

		for submission in submissions:
			count+=1
			logger.debug('Processing submission: {}'.format(submission.id))
			# Handle comments
			if isinstance(submission, praw.models.reddit.comment.Comment):
				if not comments.find_one(idint=Utils.b36(submission.id)):
					logger.debug('\t Inserting comment into database')
					self.insert_comment(submission)
				else:
					logger.debug('\t Skipping comment')
			# Handle posts
			elif isinstance(submission, praw.models.reddit.submission.Submission):
				if not posts.find_one(idint=Utils.b36(submission.id)):
					logger.debug('\t Inserting post into database')
					self.insert_post(submission)
				else:
					logger.debug('\t Skipping post')

			if not origin_log.find_one(idint=Utils.b36(submission.id)):
				origin_log.insert(dict(idint=Utils.b36(submission.id)))
				new_count+=1
		logger.info('Processed {} {} items ({} new)'.format(str(count), origin, str(new_count)))

	def insert_comment(self, comment):
		"""Inserts comment into the database"""
		if comment.author is None:
			author = '[DELETED]'
		else:
			author = comment.author.name

		# Follows timesearch's database format
		# See: https://github.com/voussoir/timesearch/blob/master/timesearch/tsdb.py#L413
		comment_data = {
			'idint': Utils.b36(comment.id),
			'idstr': comment.fullname,
			'created': comment.created_utc,
			'author': author,
			'parent': comment.parent_id,
			'submission': comment.link_id,
			'body': comment.body,
			'score': comment.score,
			'subreddit': comment.subreddit.display_name,
			'distinguish': comment.distinguished,
			'textlen': len(comment.body)
		}

		self.db['comments'].insert(comment_data)

	def insert_post(self, post):
		"""Insert post into the database"""
		if post.author is None:
			author = '[DELETED]'
		else:
			author = post.author.name

		if post.is_self:
			url = None
		else:
			url = post.url

		# Follows timesearch's database format
		# See: https://github.com/voussoir/timesearch/blob/master/timesearch/tsdb.py#L351
		post_data = {
			'idint': Utils.b36(post.id),
			'idstr': post.fullname,
			'created': post.created_utc,
			'self': post.is_self,
			'nsfw': post.over_18,
			'author': author,
			'title': post.title,
			'url': url,
			'selftext': post.selftext,
			'score': post.score,
			'subreddit': post.subreddit.display_name,
			'distinguish': post.distinguished,
			'textlen': len(post.selftext),
			'num_comments': post.num_comments,
			'flair_text': post.link_flair_text,
			'flair_css_class': post.link_flair_css_class
		}

		self.db['posts'].insert(post_data)

	def archive_saved(self, rate_limit=1000):
		logger.debug('Grabbing {} saved posts'.format(rate_limit if rate_limit else 'max'))
		saved_posts = self.reddit.user.me().saved(limit=rate_limit)
		self.process_submissions(saved_posts, 'saved')

	def archive_upvoted(self, rate_limit=1000):
		logger.debug('Grabbing {} upvoted posts'.format(rate_limit if rate_limit else 'max'))
		upvoted_posts = self.reddit.user.me().upvoted(limit=rate_limit)
		self.process_submissions(upvoted_posts, 'upvoted')


class Export:
	
	def __init__(self, config):
		logger.debug('Using config file {}'.format(config))
		cp = configparser.ConfigParser()
		cp.read(config)

		self.db = self.get_database(cp)


	def get_database(self, config):
		"""Returns a dataset db object for use with Export"""
		# First check to see if theres a db url in the config
		url = config.get('rchive', 'database')
		logger.debug('Attempting to use db url {}'.format(url))
		return dataset.connect(url)

	def export_to_format(self, file_format):
		logger.debug('Attempting export to format {}'.format(file_format))
		
		# Export URLs to text file
		if file_format == 'txt' or file_format == 'text':
			self.export_to_text()
		# Export all available submission info to JSON
		elif file_format == 'json':
			logger.error('JSON export not yet supported')
		else:
			logger.error('Unknown export format {}'.format(file_format))

		return

	def export_to_text(self):
		logger.info('Exporting submission URLs to text file...')
		filename = 'export_{}.txt'.format(datetime.now().strftime("%m-%d-%Y_%I-%M-%S_%p"))

		# Export posts
		for post in self.db['posts'].all():
			with open(filename, 'a') as f:
				# Handle link posts
				if post['url']:
					f.write(post['url'] + '\n')
				# Handle selftext posts
				else:
					f.write(Utils.build_permalink(post, 'post') + '\n')

					if args.include_selftext_urls:
						# Also export links extracted from selftext
						for url in Utils.regex_urls(post['selftext']):
							f.write(url + '\n')
		# Export comments
		for comment in self.db['comments'].all():
			with open(filename, 'a') as f:
				f.write(Utils.build_permalink(comment, 'comment') + '\n')

				if args.include_comment_urls:
					# Also export links extracted from comment body
					for url in Utils.regex_urls(comment['body']):
								f.write(url + '\n')

		# Get number of lines written to text file
		line_count = 0
		for line in open(filename).readlines():
			line_count += 1
		
		logger.info('Exported {} items to {}'.format(line_count, filename))



class Utils:
	@staticmethod
	def build_permalink(submission, submission_type):
		"""Takes a comment/post dictionary from dataset and returns a permalink to the submission"""
		idstr = submission['idstr'].split('_')[-1] # Remove t#_ prefix from submission idstr

		# Handle comments
		if submission_type == 'comment':
			parent_post_idstr = submission['submission'].split('_')[-1] # Remove prefix from submission idstr
			permalink = 'https://old.reddit.com/r/{}/comments/{}//{}/'.format(submission['subreddit'], parent_post_idstr, idstr) # Fuck new reddit
		# Handle posts
		elif submission_type == 'post':
			permalink = 'https://old.reddit.com/r/{}/comments/{}/'.format(submission['subreddit'], idstr)  # Fuck new reddit

		if args.use_new_reddit:
			permalink = permalink.replace('https://old.', 'https://')

		return permalink

	@staticmethod
	def regex_urls(string):
		urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', string)

		# Todo - Regular expressions make my brain hurt so rather than killing more of my already very few remaining brain cells, waste some memory and time and clean up any trailing symbols from all of the urls
		cleaned_urls = []
		for url in urls:
			if ')' in url:
				cleaned_urls.append(url.split(')', 1)[0])
			else:
				cleaned_urls.append(url)
		return cleaned_urls

	# B36 conversion functions thanks to voussoir:
	# https://github.com/voussoir/timesearch/blob/master/timesearch/common.py#L35-L57
	@staticmethod
	def b36(i):
		if isinstance(i, int):
			return Utils.base36encode(i)
		return Utils.base36decode(i)

	@staticmethod
	def base36decode(number):
		return int(number, 36)

	@staticmethod
	def base36encode(number, alphabet='0123456789abcdefghijklmnopqrstuvwxyz'):
		"""Converts an integer to a base36 string."""
		if not isinstance(number, (int)):
			raise TypeError('number must be an integer')
		base36 = ''
		sign = ''
		if number < 0:
			sign = '-'
			number = -number
		if 0 <= number < len(alphabet):
			return sign + alphabet[number]
		while number != 0:
			number, i = divmod(number, len(alphabet))
			base36 = alphabet[i] + base36
		return sign + base36


if __name__ == '__main__':
	# Ironically I don\'t believe rchive should archive by default, in the future I'd like to handle different functions the way timesearch does
	#  i.e. `python rchive.py archive OPTIONS`,
	#       `python rchive.py export OPTIONS`,
	# 		 etc.
	if args.skip_archive:
		logger.warning('--skip-archive passed, not archiving any saved/upvoted posts, not authing with PRAW')
	else:
		r = rchive(config=args.config)
		r.archive_all()

	if args.export:
		logger.info('--export passed, attempting to create export')
		e = Export(config=args.config)
		e.export_to_format(args.format.lower())
