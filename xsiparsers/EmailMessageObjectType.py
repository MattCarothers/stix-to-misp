import re

class EmailMessageObjectType():
	def parse(properties):
		attributes = []
		# properties.header.from_ is an "AddressObjectType"
		# with a category of 'email'.  There may also be
		# a properties.header.sender with the same structure.
		sources = []
		if properties.header.from_:
			sources.append(properties.header.from_)
		if properties.header.sender:
			sources.append(properties.header.sender)
		
		for sender in sources:
			category = sender.category
			value = sender.address_value.value
			# Refang the address
			value = value.replace('[.]', '.')
			value = value.replace('[@]', '.')
			# The value may be in the form of "Name <user@host>."
			# A MISP email-src can only contain the user@host.
			m = re.match('(.*)<(.*)>', value)
			if m:
				name  = m.group(1).rstrip()
				value = m.group(2)
				attributes.append({
					'category'     : 'Person',
					'type'         : 'text',
					'value'        : name,
					'to_ids'       : 0
				})
			# No idea why, but sometimes email sources are in the format
			# destination@victim.com [sender@attacker.com]
			m = re.search('\[(.*)\]', value)
			if m:
				value = m.group(1)
			attributes.append({
				'category'     : 'Payload delivery',
				'type'         : 'email-src',
				'value'        : value,
				'to_ids'       : 0
			})
		if properties.header.subject:
			value = properties.subject.value
			# Make sure the subject has no line breaks(???)
			value = re.sub('\n', '', value)
			attributes.append({
				'category'     : 'Payload delivery',
				'type'         : 'email-subject',
				'value'        : value,
				'to_ids'       : 0
			})
		return attributes
