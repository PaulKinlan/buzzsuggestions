import functools
from model import Session
import logging

def authorize(redirectTo = "/"):
	def factory(method):
		'Ensures that when an auth cookie is presented to the request that is is valid'
		@functools.wraps(method)
		def wrapper(self, *args, **kwargs):
		
			#Get the session parameters
			auth_id = self.request.cookies.get('auth_id', '')
			session_id = self.request.cookies.get('session_id', '')
			
			#Check the db for the session
			session = Session.GetSession(session_id, auth_id)			
			
			if session is None:
				self.redirect(redirectTo)
				return
			else:
				if session.user is None:
					self.redirect(redirectTo)
					return
					
				username = session.user.key().name()
				
				if len(args) > 0:				
					if username != "user_" + args[0]:
						# The user is allowed to view this page.
						self.redirect(redirectTo)
						return
				
			result = method(self, *args, **kwargs)
				
			return result
		return wrapper
	return factory
	
def session(method):
	'Ensures that the sessions object (if it exists) is attached to the request.'
	@functools.wraps(method)
	def wrapper(self, *args, **kwargs):
	
		#Get the session parameters
		auth_id = self.request.cookies.get('auth_id', '')
		session_id = self.request.cookies.get('session_id', '')
		
		#Check the db for the session
		session = Session.GetSession(session_id, auth_id)			
					
		if session is None:
			session = Session()
			session.session_id = Session.MakeId()
			session.auth_token = Session.MakeId()
			session.put()
		
		# Attach the session to the method
		self.SessionObj = session			
					
		#Call the handler.			
		result = method(self, *args, **kwargs)
		
		self.response.headers.add_header('Set-Cookie', 'auth_id=%s; path=/; HttpOnly' % str(session.auth_token))
		self.response.headers.add_header('Set-Cookie', 'session_id=%s; path=/; HttpOnly' % str(session.session_id))
		
		return result
	return wrapper
	
def redirect(method, redirect = "/user/"):
	'When a known user is logged in redirect them to their home page'
	@functools.wraps(method)
	def wrapper(self, *args, **kwargs):
		try:	
			if self.SessionObj is not None:
				if self.SessionObj.user is not None:
					# Check that the session is correct
					username = self.SessionObj.user.name
					

					self.redirect(redirect + username)
					return
		except:
			pass
		return method(self, *args, **kwargs)
	return wrapper