class PortObjectType():
	def parse(properties):
		attributes = []
		value = properties.port_value.value
		attributes.append({
			'category'     : 'Other',
			'type'         : 'port',
			'value'        : value,
			'to_ids'       : 0
		})
		return attributes
