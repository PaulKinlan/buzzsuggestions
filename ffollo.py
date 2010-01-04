
import wsgiref.handlers

import wsgiref.handlers
import re # Regular expressions
import random

import os
import datetime
import time

import md5
import base64
import urllib
import urllib2
from urllib2 import HTTPError
import sys
import logging


from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template

try:
	from google.appengine.api.taskqueue import Task, Queue
except:
	from google.appengine.api.labs.taskqueue import Task, Queue

from django.utils import simplejson

import friendfeed
import webdecorators
import templates
import model
import simplejsondate
import twitter

messages = { 
	'sorry' : 'We aren\'t fully open yet, please bear with us.',
	'settings-saved' : 'Settings Saved.',
	'oauth-key-error' : 'There is a problem fetching your saved searches: Error 0x01.',
	'list-created' : 'List Created.',
	'list-doesnt-exist': 'Your list no longer exists - you will not be able to follow until you choose a different list to put the results in.'
 }

def parseBoolString(theString):
	return theString[0].upper()=="T" or theString.upper() == "ON"
	
def canSubscribe(user):
	if "commands" in user:
		commands = user["commands"]
		
		if "subscribe" in commands:
			return True
		
	return False
	
def shouldSkipExcluded(username, entry):
	'''
	Determine if we should skip an entry because it is in a group the user excluded
	'''
	if "to" in entry:
		groups = entry["to"]

		for group in groups:
			if model.UserGroupExclude.IsExcluded(username, group["id"]) == True:
				return True
	
	return False
	
def isUserBlocked(username, blocks):
	'''
	Check to see if the user is blocked.
	'''
	if username in blocks:
		return True
	
	return False
	
def queueProfileFollow(username):
	try:
		t = Task(name = "profile-" + username, url = '/queue/profile', params = {"username": username}, countdown = 240)
		t.add('ffprofile')
	except:
		pass

_FRIENDFEED_API_BASE = "http://friendfeed-api.com/v2"
_FRIENDFEED_OAUTH_BASE = "https://friendfeed.com/account/oauth"

class OAuthCallbackHandler(webapp.RequestHandler):
	"""Saves the FriendFeed OAuth user data in the FF_API_AUTH cookie."""
	@webdecorators.session
	def get(self):
		request_key = self.request.get("oauth_token")
		key = self.SessionObj.request_token
		secret = self.SessionObj.token_secret			
		
		username = ""
		if 	key != request_key:
			logging.warning("Request token does not match known token")
			self.redirect("/")
			return
			
		req_token = dict(key=key, secret = secret)
		try:
			oauth_key = model.OAuthKeys.Get("friendfeed")
			
			consumer = dict(
				key = oauth_key.consumer_key,
				secret = oauth_key.consumer_secret
			)
			
			access_token = friendfeed.fetch_oauth_access_token(
				consumer, req_token)

			self.SessionObj.access_token = simplejson.dumps(access_token)
			self.SessionObj.token_secret = access_token["secret"]
			
			# Get the profile image
			username = access_token["username"]
			current_user = model.User.Get(username)
						
			#if current_user is None:
			#	current_user = model.User.CreateDefault(username)
				
			t = Task(url = '/queue/searchme', params= {"username" : username }, countdown = 240 )
			t.add('ffme-scan')
				
			t = Task(url = '/queue/searchmetype', params= {"username" : username, "type": "comments" }, countdown = 240 )
			t.add('fftype-scan')
				
			t = Task(url = '/queue/searchmetype', params= {"username" : username, "type": "likes" }, countdown = 240 )
			t.add('fftype-scan')
			
			queueProfileFollow(username)
			
				
			current_user.name = username;
			current_user.profile_img = "http://friendfeed-api.com/v2/picture/%s" % username
			current_user.access_token = self.SessionObj.access_token
			current_user.token_secret = self.SessionObj.token_secret
			
			current_user.put()
			
			self.SessionObj.user = current_user
			self.SessionObj.put()	

		except:
			logging.warning("Could not fetch access token for %r, %s %s" % (request_key, sys.exc_type, sys.exc_value))
			self.redirect("/")
			return
		
		self.redirect("/user/%s" % username )
	
	@webdecorators.session
	def post(self):
		# Save the Request Token in a cookie to verify upon callback to help
		# prevent http://oauth.net/advisories/2009-1
		oauth_key = model.OAuthKeys.Get("friendfeed")
			
		consumer = dict(
			key = oauth_key.consumer_key,
			secret = oauth_key.consumer_secret
		)
		
		token = friendfeed.fetch_oauth_request_token(consumer)
		logging.info(token)
		
		self.SessionObj.token_secret = token["secret"]
		self.SessionObj.request_token = token["key"]
		
		self.SessionObj.put()
		
		self.redirect(friendfeed.get_oauth_authentication_url(token))
		
		

class Index(webapp.RequestHandler):
	@webdecorators.session
	@webdecorators.redirect
	def get(self):
		self.response.out.write(templates.RenderThemeTemplate("index.tmpl", {}))

class Terms(webapp.RequestHandler):
	def get(self):
		self.response.out.write(templates.RenderThemeTemplate("terms.tmpl", {}))

class Contact(webapp.RequestHandler):
	def get(self):				
		self.response.out.write(templates.RenderThemeTemplate("contact.tmpl", { }))

class AboutUs(webapp.RequestHandler):
	def get(self):
		self.response.out.write(templates.RenderThemeTemplate("aboutus.tmpl", { }))
		
class Logout(webapp.RequestHandler):
	@webdecorators.session
	@webdecorators.authorize(redirectTo = "/")
	def get(self):
		self.SessionObj.delete()
		
		self.redirect('/')
		
class UserCollage(webapp.RequestHandler):
	'''
	Anyone can view a collage of all the profile images
	'''
	def get(self, username):
		
		follows = model.FollowList.GetAllFollows(username)
		self.response.out.write(templates.RenderThemeTemplate("collage.tmpl", { "follows" : follows, "username":username }))
		
class BasicSearchTerm():
	'''
	A termporary data holder.
	'''
	def __init__(self, id, name, excluded):
		self.id = id
		self.name = name
		self.excluded = excluded

class Profile(webapp.RequestHandler):
	'''
	Requests the Feed Information from a specific
	'''
	def post(self):
		username = self.request.get("username")
		
		logging.info("Getting Profile for %s" % username)
		
		profile = model.UserProfile.Get(username)
		
		service = friendfeed.FriendFeed()
		
		try:
			feed_info = service.fetch_feed_info(username, include="services")
		
			profile.profile = simplejson.dumps(feed_info)
		
			profile.put()
		except:
			pass
			
class GetTwitterOAuthToken(webapp.RequestHandler):
	def get(self):		
		request_token = self.request.get('oauth_token','')
	
		session = model.Session.GetByRequestToken(request_token)
		
		oauth_key = model.OAuthKeys.Get("twitter")
		
		consumer = dict(
				key = oauth_key.consumer_key,
				secret = oauth_key.consumer_secret
			)

		tok = twitter.fetch_oauth_access_token()		
		
		session.access_token = tok['oauth_token']

		content = twitter.verify(session.session_id, method='GET')

		# Get or create the username
		user = simplejson.loads(content)

		user_id = user["id"]

		db_user = model.User.Get(user_id)


		db_user.put()

		session.user = db_user
		session.put()
		
		
	#@authorize_session
	@webdecorators.session
	def post(self):  
		
		oauth_key = model.OAuthKeys.Get("twitter")

		consumer = dict(
				key = oauth_key.consumer_key,
				secret = oauth_key.consumer_secret
			)

		token = twitter.fetch_oauth_request_token(consumer)
	
		self.SessionObj.twitter_token_secret = token["secret"]
		self.SessionObj.twitter_request_token = token["key"]
	
		self.SessionObj.put()

		self.redirect(friendfeed.get_oauth_authorization_url(token))
		
		
class Twitter(webapp.RequestHandler):
	@webdecorators.session
	@webdecorators.authorize(redirectTo = "/")
	def get(self, username):
		pass
		

class User(webapp.RequestHandler):
	@webdecorators.session
	@webdecorators.authorize(redirectTo = "/")
	def get(self, username):
		#To get here the current user must be authorised.
		user = self.SessionObj.user
		
		oauth_key = model.OAuthKeys.Get("friendfeed")

		if oauth_key is None:
			self.response.out.write(templates.RenderThemeTemplate("user.tmpl", { "user" : user, "message_type": "error", "message" : messages['oauth-key-error'] }))
			return
			
		consumer = dict(
			key = oauth_key.consumer_key,
			secret = oauth_key.consumer_secret
		)
		
		access_token = simplejson.loads(user.access_token)

		service = friendfeed.FriendFeed(consumer, access_token)
		feedlist = service.fetch_feed_list()
		
		excludes = None;

		try:
			excludes = user.excluded_groups
		except:
			pass

		if excludes is None:
			excludes = model.UserGroupExclude(parent = user)
			excludes.name = username
			excludes.put()

			user.excluded_groups = excludes
			user.put()
					
		groups = feedlist["groups"]
		group_data = []
		for group in groups:
			if group["id"] not in excludes.groups:
				group_data.append( BasicSearchTerm(group["id"], group["name"], False))
			else:
				group_data.append( BasicSearchTerm(group["id"], group["name"], True))
		
		lists = [{"id" : "home", "name": "Home"}]
		[ lists.append(list_item) for list_item in feedlist["lists"] ]
		
		lists_all = [{"id": "default", "name":"Default" }]
		[ lists_all.append(list_item) for list_item in feedlist["lists"] ]
		
		foundList = False
		
		for list in lists:
			try:
				if list["id"] == user.settings.list_to_save:
					foundList = True
					break
			except:
				foundList = True # Although the user has not set anything up don't tell them yet.
	
		if foundList == False:
			self.response.out.write(templates.RenderThemeTemplate("user.tmpl", { "user" : user, "groups": group_data , "message_type": "error",  "message": messages['list-doesnt-exist'], "lists": lists, "lists_all": lists_all}))
		else:
			self.response.out.write(templates.RenderThemeTemplate("user.tmpl", { "user" : user, "groups": group_data , "lists": lists, "lists_all": lists_all}))
		
	@webdecorators.session
	@webdecorators.authorize(redirectTo = "/")
	def post(self, username):
		# Save the details back.
		likes_on_entry = parseBoolString(self.request.get("likes_on_entry", default_value = "false")) # People who liked my entries
		comments_on_entry  = parseBoolString(self.request.get("comments_on_entry", default_value = "false")) # People who commented on my entries
		shared_likes = parseBoolString(self.request.get("shared_likes", default_value = "false")) # People who likes on what I liked
		shared_comments = parseBoolString(self.request.get("shared_comments", default_value = "false")) # People who commented on what I commented on
		groups_input = self.request.get("groups", allow_multiple = True)
		
		selected_list = self.request.get("lists", default_value = "home")
		
		likes_on_entry_list = self.request.get("list_likes_on_entry", default_value = "default")
		comments_on_entry_list = self.request.get("list_comments_on_entry", default_value = "default")
		shared_likes_list = self.request.get("list_shared_likes", default_value = "default")
		shared_comments_list = self.request.get("list_shared_comments", default_value = 'default')
		
		user = self.SessionObj.user
		settings = None
		try:
			settings = user.settings
			if settings is None:
				settings = model.UserSettings(parent = user)
				settings.put()
				user.settings = settings
				user.put()
		except:
			# The user settings dont exist.
			settings = model.UserSettings(parent = user)
			settings.username = username
			settings.put()
			user.settings = settings
			user.put()
			
		excludes = None;

		try:
			excludes = user.excluded_groups
		except:
			pass
			
		if excludes is None:
			excludes = model.UserGroupExclude(parent = user)
			excludes.name = username

		excludes.groups = groups_input
		excludes.put()
		
		user.excluded_groups = excludes
		user.put()

			
		settings.likes_on_entry = likes_on_entry
		settings.comments_on_entry = comments_on_entry
		settings.shared_likes = shared_likes
		settings.shared_comments = shared_comments
		settings.list_to_save = selected_list
		
		settings.likes_on_entry_list = likes_on_entry_list
		settings.comments_on_entry_list = comments_on_entry_list
		settings.shared_likes_list = shared_likes_list
		settings.shared_comments_list = shared_comments_list
		
		if shared_comments:
			t = Task(url = '/queue/searchmetype', params= {"username" : username, "type": "comments" }, countdown = 240 )
			t.add('fftype-scan')
		
		if shared_likes:
			t = Task(url = '/queue/searchmetype', params= {"username" : username, "type": "likes" }, countdown = 240 )
			t.add('fftype-scan')
		
		settings.put()
		
		oauth_key = model.OAuthKeys.Get("friendfeed")
		
		if oauth_key is None:
			self.response.out.write(templates.RenderThemeTemplate("user.tmpl", { "user" : user, "message_type": "error", "message" : messages['oauth-key-error'] }))
			return
		
		consumer = dict(
			key = oauth_key.consumer_key,
			secret = oauth_key.consumer_secret
		)

		access_token = simplejson.loads(user.access_token)

		service = friendfeed.FriendFeed(consumer, access_token)
		feedlist = {"searches": []}
		
		try:
			feedlist = service.fetch_feed_list()
		except:
			logging.info("Something funky happenend for %s" % username)
			return

		groups = feedlist["groups"]
		group_data = []
		for group in groups:
			if group["id"] not in excludes.groups:
				group_data.append( BasicSearchTerm(group["id"], group["name"], False))
			else:
				group_data.append( BasicSearchTerm(group["id"], group["name"], True))

		lists = [{"id" : "home", "name": "Home"}]
		[ lists.append(list_item) for list_item in feedlist["lists"] ]

		lists_all = [{"id": "default", "name":"Default" }]
		[ lists_all.append(list_item) for list_item in feedlist["lists"] ]

		foundList = False

		for list in lists:
			try:
				if list["id"] == user.settings.list_to_save:
					foundList = True
					break
			except:
				foundList = True # Although the user has not set anything up don't tell them yet.

		if foundList == False:
			self.response.out.write(templates.RenderThemeTemplate("user.tmpl", { "user" : user, "groups": group_data, "message_type": "error",  "message": messages['list-doesnt-exist'], "lists": lists, "lists_all": lists_all}))
		else:
			self.response.out.write(templates.RenderThemeTemplate("user.tmpl", { "user" : user, "groups": group_data, "lists": lists, "lists_all": lists_all}))
			
class Searches(webapp.RequestHandler):
	@webdecorators.session
	@webdecorators.authorize(redirectTo = "/")
	def get(self, username):
		#To get here the current user must be authorised.
		user = self.SessionObj.user

		oauth_key = model.OAuthKeys.Get("friendfeed")

		if oauth_key is None:
			self.response.out.write(templates.RenderThemeTemplate("user.tmpl", { "user" : user, "message_type": "error", "message" : messages['oauth-key-error'] }))
			return

		consumer = dict(
			key = oauth_key.consumer_key,
			secret = oauth_key.consumer_secret
		)

		access_token = simplejson.loads(user.access_token)

		service = friendfeed.FriendFeed(consumer, access_token)
		feedlist = service.fetch_feed_list()

		search_data = {}

		for search in user.searchterm_set:
			search_data.udpate({search.term:search})

		excludes = None;

		try:
			excludes = user.excluded_groups
		except:
			pass

		if excludes is None:
			excludes = model.UserGroupExclude(parent = user)
			excludes.name = username
			excludes.put()

			user.excluded_groups = excludes
			user.put()

		searches = feedlist["searches"]

		for search in searches:
			if search["name"] in search_data:
				search_data[search["name"]].enabled = True
			else:
				search_term = model.SearchTerm()
				search_term.term = search["name"]
				search_term.enabled = False

				search_data[search["name"]] = search_term
		
		self.response.out.write(templates.RenderThemeTemplate("searches.tmpl", { "user" : user, "searches": searches}))

	@webdecorators.session
	@webdecorators.authorize(redirectTo = "/")
	def post(self, username):
		# Save the details back.
		user = self.SessionObj.user

		oauth_key = model.OAuthKeys.Get("friendfeed")

		if oauth_key is None:
			self.response.out.write(templates.RenderThemeTemplate("user.tmpl", { "user" : user, "message_type": "error", "message" : messages['oauth-key-error'] }))
			return

		consumer = dict(
			key = oauth_key.consumer_key,
			secret = oauth_key.consumer_secret
		)

		access_token = simplejson.loads(user.access_token)

		service = friendfeed.FriendFeed(consumer, access_token)
		feedlist = {"searches": []}

		try:
			feedlist = service.fetch_feed_list()
		except:
			logging.info("Something funky happenend for %s" % username)
			return

		search_data = {}
		searches = feedlist["searches"]
		
		for search in user.searchterm_set:
			search_data.udpate({search.term:search})

		for search in searches:
			if search["name"] in search_data:
				search_data[search["name"]].enabled = True
			else:
				search_term = model.SearchTerm()
				search_term.term = search["name"]
				search_term.enabled = False

				search_data[search["name"]] = search_term
		self.response.out.write(templates.RenderThemeTemplate("searches.tmpl", { "user" : user, "searches": searches }))

class SearchMe(webapp.RequestHandler):
	'''
	Searches the current user and enqueu any "subscribes off the back of this."
	'''
	def post(self):
		username = self.request.get("username")
		oauth_key = model.OAuthKeys.Get("friendfeed")
		enqueue = self.request.get("enqueue", default_value = "true")
		
		logging.info("Search me: %s" % username)

		if oauth_key is None:
			self.response.out.write(templates.RenderThemeTemplate("user.tmpl", { "user" : user, "message_type": "error", "message" : messages['oauth-key-error'] }))
			return
			
		user = model.User.Get(username)
		block = model.UserBlocks.Get(user)
		blocks = block.blocks
		
		if user is None:
			return

		settings = user.settings
		
		if settings is None and enqueue == "true":
			logging.info("%s does not have any settings" % username)
			t = Task(url = '/queue/searchme', params= {"username" : username }, countdown = 3600 * 12 )
			t.add('ffme-scan')
			return
		
		if settings.list_to_save is None:
			settings.list_to_save = 'home'
			
		settings.username = username 
		settings.put()
		
		consumer = dict(
			key = oauth_key.consumer_key,
			secret = oauth_key.consumer_secret
		)
		
		# Get a list of all the people that we have followed so that we can not follow them again.
		existing_follows = model.FollowList.GetAllFollows(username)

		access_token = simplejson.loads(user.access_token)

		service = friendfeed.FriendFeed(consumer, access_token)
		
		feed = {"entries": []}
		
		try:
			feed = service.fetch_feed(username)
		except:
			logging.info('SearchMeType Error: %s' % (username))
		
		counter = 0
	
		for entry in feed["entries"]:
			# If the comment is in a group that is excluded, skip
			if shouldSkipExcluded(username, entry):
				logging.info("Skipping Entry, excluded.")
				continue
			
			if settings.comments_on_entry and "comments" in entry:
				for comment in entry["comments"]:
					user_to_follow = comment["from"]["id"]
					
					if isUserBlocked(user_to_follow, blocks) == True:
						continue
					
					if canSubscribe(comment["from"]) == False:
						#logging.info("%s is already subscribed to %s" % (username, user_to_follow))
						continue
					
					if user_to_follow in existing_follows:
						continue
						
					queueProfileFollow(user_to_follow)
						
					counter = counter + 1
					
					try:
						
						t = Task(name = username + user_to_follow, countdown = 10 * counter, url =  '/follow/comment', params = { "user_a": username, "user_to_follow": user_to_follow, "comment_id": comment["id"] })
						t.add('follow-queue')
						logging.info("Enqueing Comment %s" % user_to_follow)
					except:
						pass
			
			if settings.likes_on_entry  and "likes" in entry:
				for like in entry["likes"]:

					user_to_follow =like["from"]["id"]
					
					if isUserBlocked(user_to_follow, blocks) == True:
						continue
					
					if canSubscribe(like["from"]) == False:
						#logging.info("%s is already subscribed to %s" % (username, user_to_follow))
						continue
				
					if user_to_follow  in existing_follows:
						continue
						
					queueProfileFollow(user_to_follow)
						
					counter = counter + 1
							
					try:	
						t = Task(name = username + user_to_follow, countdown = 10 * counter, url = '/follow/like', params = {"user_a": username, "user_to_follow": user_to_follow })
						t.add('follow-queue')
						logging.info("Enqueing Like %s" % user_to_follow)
					except:
						pass
					
		# Re-do this
		if enqueue == "true":
			logging.info("Requeuing")
			t = Task(url = '/queue/searchme', params= {"username" : username }, countdown = 3600 * 12 )
			t.add('ffme-scan')
		
class SearchMeType(webapp.RequestHandler):
	'''
	Searches the current user and enqueu any "subscribes off the back of this."
	'''
	def post(self):
		username = self.request.get("username")
		feed_type = self.request.get("feed_type", default_value="comments")
		enqueue = self.request.get("enqueue", default_value = "true")
		
		logging.info("Searching for %s: %s" % (username, feed_type))
		
		oauth_key = model.OAuthKeys.Get("friendfeed")

		logging.info("Search me: %s" % username)

		if oauth_key is None:
			return

		user = model.User.Get(username)
		block = model.UserBlocks.Get(user)
		blocks = block.blocks

		if user is None:
			return

		settings = user.settings
		
		if settings is None and enqueue == "true":
			logging.info("%s does not have any settings" % username)
			t = Task(url = '/queue/searchmetype', params= {"username" : username, "feed_type": feed_type }, countdown = 3600 * 12 )
			t.add('ffme-scan')
			return
			
		if settings.list_to_save is None:
			settings.list_to_save = 'home'
			#settings.put()
		
		settings.username = username 
		settings.put()
	
		consumer = dict(
			key = oauth_key.consumer_key,
			secret = oauth_key.consumer_secret
		)
		
		# Get a list of all the people that we have followed so that we can not follow them again.
		existing_follows = model.FollowList.GetAllFollows(username)

		access_token = simplejson.loads(user.access_token)

		service = friendfeed.FriendFeed(consumer, access_token)
		
		feed = {"entries": []}
		
		try:
			feed = service.fetch_feed(username +"/" + feed_type)
		except:
			logging.info('SearchMeType Error: %s -> %s' % (username, feed_type))
		
		counter = 0

		for entry in feed["entries"]:
			
			# If the comment is in a group that is excluded, skip
			if shouldSkipExcluded(username, entry):
				logging.info("Skipping Entry, excluded.")
				continue
			
			if settings.shared_comments and "comments" in entry and feed_type == "comments":
				for comment in entry["comments"]:
					# If the comment is in a group that is excluded, skip
					user_to_follow = comment["from"]["id"]
					
					if isUserBlocked(user_to_follow, blocks) == True:
						continue
					
					if canSubscribe(comment["from"]) == False:
						#logging.info("%s is already subscribed to %s" % (username, user_to_follow))
						continue
					
					if user_to_follow  in existing_follows:
						continue
					
					queueProfileFollow(user_to_follow)
					
					counter = counter + 1
					
					try:
						t = Task(name = username + user_to_follow, countdown = 20 * counter, url =  '/follow/comment', params = { "user_a": username, "user_to_follow": user_to_follow, "comment_id": comment["id"], "feed_type":feed_type })
						t.add('follow-queue')
						logging.info("Enqueing Comment %s %s" % (feed_type, user_to_follow))
					except:
						pass

			# Only follow when we are looking for shared likes
			if settings.shared_likes  and "likes" in entry and feed_type == "likes":
				for like in entry["likes"]:	
					user_to_follow =like["from"]["id"]
					
					if isUserBlocked(user_to_follow, blocks) == True:
						continue 
					
					if canSubscribe(like["from"]) == False:
						#logging.info("%s is already subscribed to %s" % (username, user_to_follow))
						continue
					
					if user_to_follow  in existing_follows:
						continue
						
					queueProfileFollow(user_to_follow)
						
					counter = counter + 1
						
					try:	
						t = Task(name = username + user_to_follow, countdown = 20 * counter, url = '/follow/like', params = {"user_a": username, "user_to_follow": user_to_follow, "feed_type":feed_type })
						t.add('follow-queue')
						logging.info("Enqueing Like %s %s" % (feed_type, user_to_follow))
					except:
						pass

		# Re-do this
		if enqueue == "true":
			logging.info("Requeuing")
			t = Task(url = '/queue/searchmetype', params= {"username" : username, "feed_type": feed_type }, countdown = 3600 * 12 )
			t.add('fftype-scan')
			
class RecentFollows(webapp.RequestHandler):
	@webdecorators.session
	@webdecorators.authorize(redirectTo = "/")
	def get(self):
		feed_type = ""
			
class Search(webapp.RequestHandler):
	def post(self):
		username = self.request.get("username")
		search_term = self.request.get("search")
		feed_type = "search"
		enqueue = self.request.get("enqueue", default_value = "true")
		
		logging.info("Searching for %s %s: %s" % (username, search_term, feed_type))
		
		oauth_key = model.OAuthKeys.Get("friendfeed")

		logging.info("Search me: %s" % username)

		if oauth_key is None:
			self.response.out.write(templates.RenderThemeTemplate("user.tmpl", { "user" : user, "message_type": "error", "message" : messages['oauth-key-error'] }))
			return

		user = model.User.Get(username)
		block = model.UserBlocks.Get(user)
		blocks = block.blocks
		
		access_token = simplejson.loads(user.access_token)

		service = friendfeed.FriendFeed(consumer, access_token)
		
		try:
			feed = service.search(search_term)
		except:
			logging.info('Search Error: %s' % (term))

		counter = 0

		if user is None:
			return

		settings = user.settings
		
		if settings is None and enqueue == "true":
			logging.info("%s does not have any settings" % username)
			t = Task(url = '/queue/search', params= {"username" : username, "search": search_term }, countdown = 3600 * 12 )
			t.add('ffsearch')
			return
		
		if settings.list_to_save is None:
			settings.list_to_save = 'home'
			
		settings.username = username 
		settings.put()
		
		consumer = dict(
			key = oauth_key.consumer_key,
			secret = oauth_key.consumer_secret
		)
		
		# Get a list of all the people that we have followed so that we can not follow them again.
		existing_follows = model.FollowList.GetAllFollows(username)

		access_token = simplejson.loads(user.access_token)

		service = friendfeed.FriendFeed(consumer, access_token)

		feed = {"entries": []}
		
		try:
			feed = service.fetch_search_feed(search_term)
		except:
			pass
			
		for entry in feed["entries"]:
			# If the comment is in a group that is excluded, skip
			if shouldSkipExcluded(username, entry):
				logging.info("Skipping Entry, excluded.")
				continue
			
			for comment in entry["comments"]:
				user_to_follow = comment["from"]["id"]
				
				if isUserBlocked(user_to_follow, blocks) == True:
					continue
				
				if canSubscribe(comment["from"]) == False:
					#logging.info("%s is already subscribed to %s" % (username, user_to_follow))
					continue
				
				if user_to_follow  in existing_follows:
					continue
				
				counter = counter + 1
				
				try:
					t = Task(name = username + user_to_follow, countdown = 20 * counter, url =  '/follow/comment', params = { "user_a": username, "user_to_follow": user_to_follow, "comment_id": comment["id"], "feed_type":feed_type })
					t.add('follow-queue')
					logging.info("Enqueing Comment %s %s" % (feed_type, user_to_follow))
				except:
					pass
					
			for comment in entry["likes"]:
				user_to_follow = comment["from"]["id"]
				
				if isUserBlocked(user_to_follow, blocks) == True:
					continue

				if canSubscribe(comment["from"]) == False:
					#logging.info("%s is already subscribed to %s" % (username, user_to_follow))
					continue

				if user_to_follow  in existing_follows:
					continue

				counter = counter + 1

				try:
					t = Task(name = username + user_to_follow, countdown = 20 * counter, url =  '/follow/comment', params = { "user_a": username, "user_to_follow": user_to_follow, "comment_id": comment["id"], "feed_type":feed_type })
					t.add('follow-queue')
					logging.info("Enqueing Comment %s %s" % (feed_type, user_to_follow))
				except:
					pass
					
		if enqueue == "true":
			logging.info("Requeuing")
			t = Task(url = '/queue/searchme', params= {"username" : username, "feed_type": feed_type }, countdown = 3600 * 12 )
			t.add('fftype-scan')

class FollowComment(webapp.RequestHandler):
	def post(self):
		username = self.request.get("user_a")
		user_to_follow = self.request.get("user_to_follow")
		comment_id = self.request.get("comment_id")
		feed_type = self.request.get("feed_type", default_value = 'comment')
	
		if username == user_to_follow:
			return
		
		oauth_key = model.OAuthKeys.Get("friendfeed")
		user = model.User.Get(username)
			
		if user is None:
			return
			
		if feed_type == '' and user.settings.comments_on_entry == False:
			logging.info("%s no longer wants to follow comments on own entries" % (username))
			return

		if feed_type != '' and user.settings.shared_comments == False:
			logging.info("%s no longer wants to follow shared comments" % (username))
			return
		
		if model.FollowList.IsFollowing(username, user_to_follow):
			logging.info("%s Already Followed User %s" %(username, user_to_follow))
			return
		
		consumer = dict(
			key = oauth_key.consumer_key,
			secret = oauth_key.consumer_secret
			)
			
			
		access_token = simplejson.loads(user.access_token)
			
		service = friendfeed.FriendFeed(consumer, access_token)
		result = ""
		try:
			list_to_add = user.settings.list_to_save

			if feed_type == "comment" and user.settings.comments_on_entry_list != "default":
				list_to_add = user.settings.comments_on_entry_list
			if feed_type == "comments" and user.settings.shared_comments_list != "default":
				list_to_add = user.settings.shared_comments_list
			
			logging.info("%s to follow %s -> %s" % (username, user_to_follow, list_to_add))
			
			result = service.subscribe(user_to_follow, list=list_to_add)
		except HTTPError, e:
			logging.info(e.read())
			return
			
			
		
		follow = model.Follow(parent = user)
		follow.username = user_to_follow
		follow.type = feed_type
		follow.put()
		
		model.FollowList.Add(user, user_to_follow)
		
		logging.info("%s Subscribed to %s via comment %s: %s" % (username, user_to_follow, comment_id, result))

class FollowLike(webapp.RequestHandler):
	def post(self):
		username = self.request.get("user_a")
		user_to_follow = self.request.get("user_to_follow")
		feed_type = self.request.get("feed_type", default_value = 'like')
		
		if username == user_to_follow:
			return
			
		oauth_key = model.OAuthKeys.Get("friendfeed")
		user = model.User.Get(username)
		
		if user is None:
			return
			
		if feed_type == '' and user.settings.likes_on_entry == False:
			logging.info("%s no longer wants to follow likes on own entries" % (username))
			return
		
		if feed_type != '' and user.settings.shared_likes == False:
			logging.info("%s no longer wants to follow shared likes" % (username))
			return
			
		if model.FollowList.IsFollowing(username, user_to_follow):
			logging.info("%s Already Followed User %s" %(username, user_to_follow))
			return
			
		consumer = dict(
			key = oauth_key.consumer_key,
			secret = oauth_key.consumer_secret
			)
			
		access_token = simplejson.loads(user.access_token)
			
		service = friendfeed.FriendFeed(consumer, access_token)
		
		result = ""
		try:
			
			list_to_add = user.settings.list_to_save
			
			if feed_type == "like" and user.settings.likes_on_entry_list != "default":
				list_to_add = user.settings.likes_on_entry_list
			if feed_type == "likes" and user.settings.shared_likes_list != "default":
				list_to_add = user.settings.shared_likes_list
			
			logging.info("%s to follow %s -> %s" % (username, user_to_follow, list_to_add))

			
			result = service.subscribe(user_to_follow, list=list_to_add)
		except HTTPError, e:
			logging.info(e.read())
			return
		
		follow = model.Follow(parent = user)
		follow.username = user_to_follow
		follow.type = feed_type
		follow.put()
		
		model.FollowList.Add(user, user_to_follow)
		
		logging.info("%s Subscribed to %s via like: %s" % (username, user_to_follow, result))


class CreateService(webapp.RequestHandler):
	def get(self):
		service = self.request.get("service")
		key = self.request.get("key")
		secret = self.request.get("secret")
		
		keys = model.OAuthKeys.Create(service, key, secret)
		
		self.response.out.write("%s" % (keys.key().name()))
		
class CreateBlock(webapp.RequestHandler):
	@webdecorators.session
	@webdecorators.authorize(redirectTo = "/")
	def post(self):
		username = self.request.get("username") # The user to block
		user = self.SessionObj.user
		
		block = model.UserBlocks.Get(user) 
		
		block.Add(username)
		
		self.redirect('/user/' + user.name + '/blocks')
		
class Blocks(webapp.RequestHandler):
	@webdecorators.session
	@webdecorators.authorize(redirectTo = "/")
	def get(self, username):
		
		user = self.SessionObj.user
		blocks = model.UserBlocks.Get(user)
		
		self.response.out.write(templates.RenderThemeTemplate("blocks.tmpl", { "blocks" : blocks }))
		
def main():
	application = webapp.WSGIApplication(
		[
			(r'/', Index),
			(r'/contact', Contact),
			(r'/terms', Terms),
			(r'/session/destroy', Logout),
			(r'/block/create', CreateBlock),
			(r'/createservice', CreateService),
			(r'/queue/searchme', SearchMe),
			(r'/queue/searchmetype',SearchMeType),
			(r'/queue/profile', Profile),
			(r'/aboutus', AboutUs),
			(r'/follow/comment', FollowComment),
			(r'/follow/like', FollowLike),
			(r'/oauth_callback', OAuthCallbackHandler),
			(r'/user/([^/]+)', User),
			(r'/user/([^/]+)/collage', UserCollage),
			(r'/user/([^/]+)/blocks', Blocks),
			(r'/user/([^/]+)/searches', Searches),
			(r'/user/([^/]+)/twitter', Twitter),
			(r'/get_twitter_oauth_token', GetTwitterOAuthToken)
			
		], debug = False)
		
	wsgiref.handlers.CGIHandler().run(application)

if __name__ == "__main__":
	main()