class AddressObjectType():
	def parse(properties):
		attributes = []
		category = properties.category
		value = properties.address_value.value.rstrip()
		# Refang the address
		value = value.replace('[.]', '.')
		value = value.replace('[d]', '.')
		value = value.replace('[@]', '@')
		if category == 'e-mail':
			attributes.append({
				'category'     : 'Payload delivery',
				'type'         : 'email-src',
				'value'        : value,
				'to_ids'       : 0,
			})
		else:
			# There will probably be an ipv6-addr someday
			assert category == 'ipv4-addr'
			# Most indicators don't include an is_source or is_destination.
			# We'll default to is_source.
			if properties.is_source or not properties.is_destination:
				misp_type = 'ip-src'
			else:
				misp_type = 'ip-dst'
			attributes.append({
				'category'     : 'Network activity',
				'type'         : misp_type,
				'value'        : value,
				'to_ids'       : 1,
			})
		return attributes
