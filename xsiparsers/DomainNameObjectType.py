import re

class DomainNameObjectType():
	def parse(properties):
		attributes = []
		value = properties.value.value.rstrip()
		# Refang the domain
		value = value.replace('[.]', '.')
		value = value.replace('[d]', '.')
		# GIGO
		if re.search('/', value):
			# This is a URL stored as a domain
			attributes.append({
				'category'     : 'Network activity',
				'type'         : 'uri',
				'value'        : value,
				'to_ids'       : 1
			})
		else:
			attributes.append({
				'category'     : 'Network activity',
				'type'         : 'domain',
				'value'        : value,
				'to_ids'       : 1
			})
		return attributes
