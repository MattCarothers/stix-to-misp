class WhoisObjectType():
	def parse(properties):
		attributes = []
		value = str(properties.remarks)
		attributes.append({
			'category'     : 'Attribution',
			'type'         : 'text',
			'value'        : value,
			'to_ids'       : 0
		})
		return attributes
