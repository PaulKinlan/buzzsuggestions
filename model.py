from google.appengine.ext import db
from google.appengine.api import memcache

from django.utils import simplejson

import logging
import re
import random


from utils import selfmemoize, memoize

class JsonModel(db.Model): 
	def to_json(self): 
		data = {} 
		for prop in self.properties().values(): 
			if not isinstance(prop, db.ReferenceProperty) :
				data[prop.name] = prop.get_value_for_datastore(self) 
		return simplejson.dumps(data) 
	
	def to_dict(self): 
		data = {} 
		for prop in self.properties().values(): 
			if not isinstance(prop, db.ReferenceProperty) :
				data[prop.name] = prop.get_value_for_datastore(self) 
		return data

class OAuthKeys(JsonModel):
	consumer_key = db.StringProperty()
	consumer_secret = db.StringProperty()
	
	@staticmethod
	def Get(service):
		return OAuthKeys.get_by_key_name(service)
		
	@staticmethod
	def Create(service, key, secret):
		'''
		Creates an oAuth key so it is not stored in the database.
		'''
		keys = OAuthKeys.Get(service)
		
		if keys is not None:
			return keys
		
		keys = OAuthKeys(key_name = service)
		keys.consumer_key = key
		keys.consumer_secret = secret
		keys.put()
		
		return keys;
			
		
class UserSettings(JsonModel):
	'''
	The settings a user has setup.
	'''
	added_on = db.DateTimeProperty(auto_now_add = True)
	last_update = db.DateTimeProperty(auto_now = True)
	username = db.StringProperty()
	
	likes_on_entry = db.BooleanProperty(default = False) # People who liked my entries
	likes_on_entry_list = db.StringProperty(default = 'default')
	comments_on_entry  = db.BooleanProperty(default = False) # People who commented on my entries
	comments_on_entry_list = db.StringProperty(default = 'default')
	shared_likes = db.BooleanProperty(default = False) # People who likes on what I liked
	shared_likes_list = db.StringProperty(default = 'default')
	shared_comments = db.BooleanProperty(default = False) # People who commented on what I commented on
	shared_comments_list = db.StringProperty(default = 'default')
	
	list_to_save = db.StringProperty(default = 'home')
	
class UserBlocks(JsonModel):
	'''
	A List of the blocks that a user has performed.
	'''
	name = db.StringProperty()
	blocks = db.StringListProperty()
	
	@staticmethod
	def Get(user):
		b = UserBlocks.get_or_insert("block_" + user.name, parent = user, name = user.name)
		
	 	return b
	
	def Add(self, user):
		'''
		Adds a user into the block
		'''
		if user not in self.blocks:
			self.blocks.append(user)
			self.put()
	

class UserGroupExclude(JsonModel):
	'''
	A list of the groups that the user does not want to follow in.
	'''
	added_on = db.DateTimeProperty(auto_now_add = True)
	updated_on = db.DateTimeProperty(auto_now = True)
	name = db.StringProperty() # The username is used for convinience
	groups = db.StringListProperty()
	
	@staticmethod
	@memoize("UserGroupExclude:IsExcluded:%s %s")
	def IsExcluded(name, group):
		'''
		Checks to see if a user is excluded from a group.
		'''
		result = UserGroupExclude.GetForUser(name)
		
		if result is None:
			return False
			
		if group in result.groups:
			return True
		
		return False
		
	@staticmethod
	@memoize("UserGroupExclude:GetForUser:%s")
	def GetForUser(name):
		'''
		Gets a users Group exclude list.
		
		This method is cahced so that the check is very quick
		'''
		return db.Query(UserGroupExclude).filter("name =", name).get()
						
class User(JsonModel):
	name = db.StringProperty()
	profile_img = db.StringProperty()
	is_private = db.BooleanProperty(default = False) # Some users might be private so hide their details, only allow their friends to see their boo's
		
	last_updated = db.DateTimeProperty(auto_now = True)
	added_on = db.DateTimeProperty(auto_now_add = True)
	
	settings = db.ReferenceProperty(UserSettings)
	excluded_groups = db.ReferenceProperty(UserGroupExclude)
	
	#OAuth information is attached to the user
	access_token = db.StringProperty()
	token_secret = db.StringProperty()
	
	# OAuth Password based Auth.
	pwd_access_token = db.StringProperty()
	
	@staticmethod
	#@memoize("User:%s")	
	def Get(username):
		return User.get_or_insert("user_%s" % username, name = username)
		
	@staticmethod
	#@memoize("User:%s")	
	def GetLatest():
		return db.Query(User).order("-added_on").fetch(5)
	
	@staticmethod
	#@memoize("User:%s")	
	def GetRecentUpdates():
		return db.Query(User).order("-last_update").fetch(5)
	
	def Update(self):
		'Updates the settings and clears the cache.'
		memcache.set("User:%s" % self.name, self, 60)		
		self.put()

class UserProfile(JsonModel):
	'''
	A Cache of the User Profile infortmation from Twitter
	'''
	name = db.StringProperty()
	added_on = db.DateTimeProperty(auto_now_add = True)
	updated_on = db.DateTimeProperty(auto_now = True)
	profile = db.TextProperty() # A Json Structure of the Friendfeed profile
	
	@staticmethod
	def Get(username):
		return UserProfile.get_or_insert("user_%s" % username, name = username)

class UserServices(JsonModel):
	'''
	A user can be a member of many services, such as Twitter, Facebook, laconica etc.
	'''
	name = db.StringProperty()
	user = db.ReferenceProperty(User)

	service = db.StringProperty() # The name of the service, Twitter etc.
	auth_type = db.StringProperty() # Oauth, username, facebook etc
	#OAuth information is attached to the user
	access_token = db.StringProperty()
	token_secret = db.StringProperty()

	# If OAuth is not used then it is likely that a username and password is used - unless it is facebook.
	username = db.StringProperty()
	password = db.StringProperty()

class Follow(JsonModel):
	'''
	A user will follow people.
	'''
	added_on = db.DateTimeProperty(auto_now_add = True)
	username = db.StringProperty() # The user we followed.
	type = db.StringProperty()
	
class SearchTerm(JsonModel):
	'''
	A search term is somthing that we search for on friend feed
	'''
	username = db.StringProperty()
	user = db.ReferenceProperty(User)
	added_on = db.DateTimeProperty(auto_now_add = True)
	updated_on = db.DateTimeProperty(auto_now = True)
	enabled = db.BooleanProperty(default = False)
	term = db.StringProperty()
	entry = db.StringProperty()
	likes_on_entry = db.BooleanProperty(default = False) # People who liked the entry
	comments_on_entry  = db.BooleanProperty(default = False) # People who commented the entry
	list_to_save = db.StringProperty(default = 'home') # The list that we save follows into.
	
	
class FollowList(JsonModel):
	username = db.StringProperty() # The current user
	count = db.IntegerProperty()
	follows = db.StringListProperty()
	
	@staticmethod
	def Get(username):
		return db.Query(FollowList).filter("username =", username).fetch(10)
		
		
	@staticmethod
	def IsFollowing(username, follower):
		following = db.Query(FollowList, keys_only = True).filter("username =", username).filter("follows =", follower).get()
		if following is not None:
			return True
		return False
		
	@staticmethod
	def GetAllFollows(username):
		'''
		Gets a combined array of all the people a user has followed, quicker to search that way.
		'''
		follows = FollowList.Get(username) 
		follow_list = []
		
		for follow in follows:
			for _follow in follow.follows:
				follow_list.append(_follow)
		
		return follow_list
		
	@staticmethod
	def Add(user, user_to_follow):
		
		follows =  db.Query(FollowList).filter("username =", user.name).filter("count <", 1000).get() # Get the follow list that has less than 1000 entries.  This allows for sharding
		
		if follows is None:
			# There is no entity that has less that x follows in it, make a new one to start adding to.
			follows = FollowList(parent = user)
			follows.username = user.name
			
		follows.follows.append(user_to_follow)
		
		follows.count = len(follows.follows)
		follows.put()
	
		
class Session(db.Model):
	'The Session Model links a logged in session to a user'
	user = db.ReferenceProperty(User)
	session_id = db.StringProperty()
	auth_token = db.StringProperty()
	
	#OAuth Stuff
	request_token = db.StringProperty()
	access_token = db.StringProperty()
	token_secret = db.StringProperty()
	oauth_verifier = db.StringProperty()
	
	added_on = db.DateTimeProperty(auto_now_add = True)
	last_accessed_on = db.DateTimeProperty(auto_now = True)
	
	@staticmethod
	def GetSession(session_id, auth_token):
		return db.Query(Session).filter("session_id =", session_id).filter("auth_token =", auth_token).get()
		
	@staticmethod
	def GetByTokenSecret(token_secret):
		return db.Query(Session).filter("token_secret =", token_secret).get()
	
	@staticmethod
	def GetByRequestToken(request_token):
		return db.Query(Session).filter("request_token =", request_token).get()
	
	@staticmethod
	def MakeId():
		guid = 'amp' + ''.join([random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890abcdefghijklmnopqrstuvwxyz') for i in range(60)])
		return guid	