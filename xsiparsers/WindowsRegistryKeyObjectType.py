class WindowsRegistryKeyObjectType():
	def parse(properties):
		attributes = []
		if properties.hive:
			value = properties.hive.value + properties.key.value
		else:
			value = properties.key.value
		attributes.append({
			'category'     : 'Artifacts dropped',
			'type'         : 'regkey',
			'value'        : value,
			'to_ids'       : 0
		})
		return attributes
