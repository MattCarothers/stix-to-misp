import re

class FileObjectType():
	def parse(properties):
		attributes = []
		file_name = str(properties.file_name)
		if file_name == 'UNDER NCCIC REVIEW':
			# *Scratches head*
			return []
		if re.match('rule selector', file_name):
			# Yara rule stored as a file name
			return []
		# Create a filename|hash attribute for each hash in this Cybox object
		if properties.hashes:
			for hash_ in properties.hashes:
				# hash_type is e.g. MD5, SHA256, SSDEEP, etc
				hash_type = hash_.type_.value
				# The hash may have either a simple value or a fuzzy one
				if hash_.simple_hash_value:
					hash_value = hash_.simple_hash_value.value
				elif hash_.fuzzy_hash_value:
					hash_value = hash_.fuzzy_hash_value.value
				else:
					raise AttributeError("Hash has neither a simple nor a fuzzy value")

				# GIGO.  Sometimes the wrong hash type is set
				if re.match('^[a-fA-F0-9]{32}$', hash_value):
					hash_type = "md5"
				if re.match('^[a-fA-F0-9]{40}$', hash_value):
					hash_type = "sha1"
				if re.match('^[a-fA-F0-9]{64}$', hash_value):
					hash_type = "sha256"

				# This will either be a MISP filename|hash or just a hash
				if properties.file_name:
					value = "|".join([file_name, hash_value])
					misp_type = 'filename|' + hash_type
				else:
					value = hash_value
					misp_type = hash_type

				attributes.append({
					'category'     : 'Artifacts dropped',
					'type'         : misp_type.lower(),
					'value'        : value,
					'to_ids'       : 1
				})
		else:
			# File object with no hashes.  Assume it at least
			# has a name.
			assert properties.file_name != None
			value = file_name
			attributes.append({
				'category'     : 'Artifacts dropped',
				'type'         : 'filename',
				'value'        : value,
				'to_ids'       : 0
			})
		# TODO PDFFileObjectType has other fields, such as metadata
		return attributes
