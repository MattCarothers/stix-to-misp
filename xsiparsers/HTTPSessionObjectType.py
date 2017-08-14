class HTTPSessionObjectType():
	def parse(properties):
		attributes = []
		attributes.append({
			'category'     : 'Network activity',
			'type'         : 'text',
			'value'        : json.dumps(properties.to_dict(), indent=1),
			'to_ids'       : 0
		})
		return attributes
