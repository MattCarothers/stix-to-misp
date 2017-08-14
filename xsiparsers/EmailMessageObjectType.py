import re

class EmailMessageObjectType():
	def parse(properties):
		attributes = []
		# properties.header.from_ is an "AddressObjectType"
		# with a category of 'email'
		if properties.header.from_:
			from_ = properties.header.from_
			f_xsi_type = from_._XSI_TYPE
			category = from_.category
			value = from_.address_value.value
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
			attributes.append({
				'category'     : 'Payload delivery',
				'type'         : 'email-src',
				'value'        : value,
				'to_ids'       : 0
			})
		if properties.header.subject:
			value = properties.subject.value
			attributes.append({
				'category'     : 'Payload delivery',
				'type'         : 'email-subject',
				'value'        : value,
				'to_ids'       : 0
			})
		return attributes
