import re

class LinkObjectType():
	def parse(properties):
		attributes = []
		value = properties.value.value.rstrip()
		# Refang the URL
		value = value.replace('hxxp', 'http')
		value = value.replace('[.]', '.')
		value = value.replace('[:]', ':')
		value = value.replace('. ', '.')
		value = value.replace(' .', '.')
		# Sometimes URLs have line breaks in them for some
		# inexplicable reason.
		value = re.sub('\s+', '', value)
		attributes.append({
			'category'     : 'Network activity',
			'type'         : 'uri',
			'value'        : value,
			'to_ids'       : 1
		})
		return attributes
