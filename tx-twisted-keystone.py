import ConfigParser, os, json

from zope.interface import implements
from twisted.cred import portal, checkers, credentials, error as credError
from twisted.internet import defer, reactor
from twisted.web import static, resource
from twisted.web.resource import Resource, IResource
from twisted.web.http import HTTPChannel
from twisted.web import server
from twisted.web.guard import HTTPAuthSessionWrapper
from twisted.web.guard import BasicCredentialFactory

from keystonemiddleware.auth_token import AuthProtocol, InvalidUserToken


class TokenChecker(object):
	"""Verifies token credentials against Keystone."""

	implements(checkers.ICredentialsChecker)
	credentialInterfaces = (credentials.IUsernamePassword,)

	def __init__(self, auth_protocol, delay_auth_decision, enforce_roles):
		self.auth_protocol = auth_protocol
		self.enforce_roles = enforce_roles
		self.delay_auth_decision = delay_auth_decision
	  
	def requestAvatarId(self, credentials):
		token_info = None
		try:
			user = credentials.username
			user_token = credentials.password
			if user != 'TOKEN' or not user_token:
				raise InvalidUserToken(
					"Credentials must follow the TOKEN:<uuid_token> pattern")
			token_info = self.auth_protocol._validate_user_token(user_token, {})
			roles = [role['name'] for role in token_info['token']['roles']]
			for role in self.enforce_roles:
				if not role in roles:
					raise InvalidUserToken
			return defer.succeed({'authorized': True, 'token': token_info})
		except InvalidUserToken as ex:
			# Just pass empty token info and let the service decide what to do.
			if self.delay_auth_decision:
				return defer.succeed({'authorized': False, 'token': token_info})
			else:
				return defer.fail(credError.UnauthorizedLogin(
					ex.message or "Invalid user token"))


class ProtectedRealm(object):
	implements(portal.IRealm)

	def __init__(self, protectedResource):
		self.protectedResource = protectedResource

	def requestAvatar(self, auth_info, mind, *interfaces):
		if IResource in interfaces:
			self.protectedResource.keystone_authorized = auth_info['authorized']
			self.protectedResource.keystone_token_info = auth_info['token']
			return (IResource, self.protectedResource, lambda: None)
		raise NotImplementedError()


class ResourceShield(object):
	"""Protects resources by requiring appropriate token credentials."""

	def __init__(self, config_file_name=None, config_override=None):
		"""Specify config_file_name if you want to read the configuration from
		there instead of from what's specified by TWISTED_KEYSTONE_CONFIG env
		var. You can override options by passing a dict via config_override.
		"""
		config = self._getConfig(config_file_name, config_override)
		self.auth_protocol = AuthProtocol(None, config)
		self.auth_protocol._token_cache.initialize({})

	def _getConfig(self, config_file_name, config_override):
		config_file_name = config_file_name or os.environ.get(
			'TWISTED_KEYSTONE_CONFIG')
		if config_file_name:
			parser = ConfigParser.ConfigParser()
			parser.read(config_file_name)
			config = {}
			for option, value in parser.items('config'):
				try:
					# We need typed values (not strs). Parse them with json.
					value = json.loads(value)
				except ValueError:
					pass
				config[option] = value
		else:
			# Minimum required configuration options
			config = {'auth_protocol': 'http', 'admin_token': 'ADMIN'}
			if config_override:
				config.update(config_override)
		return config

	def protectResource(self, resource, delay_auth_decision=False,
		enforce_roles=[]):
		"""Protect the given resource by enforcing token based auth.

		If delay_auth_decision is False, unauthorized requests are replied with
		an HTTP 401 error response. Otherwise, all requests will be allowed to
		pass delegating the final auth decision to the service itself.
		Authorized resources are flagged by setting the keystone_authorized
		field to True. Also, the retrieved token info is stored in the
		keystone_token_info field. All roles passed in enforce_roles will be
		checked against the token. If any of them is missing, the request will
		not be authorized.
		"""
		p = portal.Portal(ProtectedRealm(resource),
			[TokenChecker(
				self.auth_protocol, delay_auth_decision, enforce_roles)])
		if hasattr(resource, 'name'):
			name = resource.name
		else:
			name = ""
		return HTTPAuthSessionWrapper(p, [BasicCredentialFactory(name)])


class ServiceRoot(Resource):
	"""A simple resource that injects auth info to every passing request."""

	def __init__(self, name):
		Resource.__init__(self)
		self.name = name

	def getChildWithDefault(self, path, request):
		request.keystone_authorized = self.keystone_authorized
		request.keystone_token_info = self.keystone_token_info
		return resource.Resource.getChildWithDefault(self, path, request)


class MyResource(Resource):

	def __init__(self):
		resource.Resource.__init__(self)

	def getChild(self, path, request):
		if request.keystone_authorized:
			text = "AUTHORIZED. This is your token: %s"
		else:
			text = "UNAUTHORIZED. This is your token: %s"
		text = text  % json.dumps(request.keystone_token_info, indent=4)
		return static.Data(text, "text/plain")


if __name__ == "__main__":
	# Usage example.
	shield = ResourceShield()
	root = ServiceRoot("Test service")
	root.putChild("example", MyResource())
	site = server.Site(shield.protectResource(root))
	site.protocol = HTTPChannel
	reactor.listenTCP(8801, site)
	reactor.run()