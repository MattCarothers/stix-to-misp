#!/usr/bin/python3 -W ignore

# stix-to-misp takes a STIX package XML file as input and feeds it into MISP
# (http://www.misp-project.org/).  It's written for AIS and CISCP, so it may
# or may not work with any other STIX input.
#
# usage: stix-to-misp.py [-h] [-u MISP_URL] -k MISP_KEY [-v VERIFY_CERT]
#                        [-d DISTRIBUTION] [-t TAGS] [-l LEVEL]
#                        input_file
# 
# positional arguments:
#   input_file            An AIS or CISCP XML STIX Package file
#
# optional arguments:
#   -h, --help            show this help message and exit
#   -u MISP_URL, --misp-url MISP_URL
#                         MISP server URL (default to https://localhost)
#   -k MISP_KEY, --misp-key MISP_KEY
#                         MISP API key
#   -v VERIFY_CERT, --verify-cert VERIFY_CERT
#                         Verify TLS certificate (defaults to true)
#   -d DISTRIBUTION, --distribution DISTRIBUTION
#                         MISP Event distribution (org, community, connected,
#                         all, or a sharing group UUID)
#   -t TAGS, --tags TAGS  MISP Event tags (use multiple times to set more than
#                         one tag)
#   -l LEVEL, --level LEVEL
#                         MISP threat level (high, medium, low, or undefined -
#                         defaults to low)

import argparse
import json
import re
import requests
import sys
import uuid

from dateutil import parser
from stix.core import STIXPackage, STIXHeader
import stix.extensions.marking.ais

import xsiparsers

# Create MISP attributes from a Cybox object.  Recursively create
# attributes from related objects.
def create_attributes(object_, parent_value=None, misp_comment=None, indicator_timestamp=None, deref={}):
	# ident to make output more readable
	indent = "   "

	# This object might be a relation with an idref instead of an id
	if object_.idref:
		if object_.idref in deref:
			object_ = deref[object_.idref]
		else:
			# We've already created this attribute, and the
			# id has been popped from our object map.
			return []


	id_ = object_.id_

	# Remove the object from the reference map, so we
	# can clean up later by outputting all the objects
	# that never got referenced.  This also prevents
	# infinite recursion between objects with circular
	# relations.
	deref.pop(id_, None)

	# Sometimes CISCP includes empty objects that don't even have an id
	if not id_:
		print(indent, "Empty Object?  No ID.", json.dumps(object_.to_dict(), indent=1))
		return []

	# Sometimes AIS includes objects with no properties.  E.g. there will be a
	# 'Resolved_To' relationship for an IP that doesn't have reverse DNS.
	if not object_.properties:
		print(indent, ", ".join([id_, "NO PROPERTIES"]))
		return []

	properties = object_.properties

	# Is this a related object?  If so, we'll put the relationship
	# in the MISP attribute comment.
	if hasattr(object_, 'relationship'):
		# object_.relationship.value is e.g. "Resolved_To"
		# Set relationship_text to e.g. "resolved to"
		relationship_text = object_.relationship.value.lower().replace('_', ' ')

		# This shouldn't happen
		if parent_value == None:
			print(json.dumps(object_.to_dict(), indent=1))
		assert parent_value != None

		parent_value = str(parent_value)
		# misp_comment set to e.g. "1.2.3.4 resolved to this"
		misp_comment = parent_value + " " + relationship_text + " this"
		indent = indent + "   " + parent_value + " " + object_.relationship.value + ":"

	# List to hold the MISP attributes
	attributes = []

	# Create a MISP object based on the xsi:type of the Cybox object
	xsi_type = properties._XSI_TYPE

	# Set an initial value as a placeholder
	value = xsi_type + '-' + id_

	# Do we have a parser module for this xsi:type?
	if hasattr(xsiparsers, xsi_type):
		# Run the parser
		parser = getattr(xsiparsers, xsi_type)
		attributes = parser.parse(properties)
		# If we got attributes back from the parser, add some additional MISP
		# fields.  Also set the 'value' variable, which we'll use later if there
		# are related objects and we need to recurse.
		for attribute in attributes:
			if attribute['type'] != 'text':
				value = attribute['value']
			print(indent, ", ".join([id_, xsi_type, attribute['type'], str(value)]))
			attribute['distribution'] = 5
			attribute['timestamp']    = indicator_timestamp
			# The comment field will be the indicator description (if there is one) or
			# information about the relationship to the parent object if this is a child
			if misp_comment:
				attribute['comment'] = misp_comment
	else:
		# No parser module for this xsi:type
		print(indent, ", ".join([id_, xsi_type, "???"]))
		print(json.dumps(properties.to_dict(), indent=1))
		raise AttributeError("Unknown xsi:type")

	# There may be related objects.  Recursively parse them.
	if object_.related_objects:
		for related_object in object_.related_objects:
			if related_object.idref and related_object.idref in deref:
				# If this related object has an idref, we need to store the relationship,
				# dereference the object, and add the relationship to the reference object
				relationship = related_object.relationship
				related_object = deref[related_object.idref]
				related_object.relationship = relationship
			# Recurse
			attributes = attributes + create_attributes(related_object, value, indicator_timestamp=indicator_timestamp, deref=deref)
	return attributes

def parse_package(input_file):
	# Open the STIX package file and parse it
	fh = open(input_file)
	print("###", input_file)
	pkg = STIXPackage.from_xml(fh)
	if not pkg.indicators:
		print("No indicators")
	print("ID:   ", pkg.id_)
	# Extract a UUID from the STIX Package ID.
	# E.g. NCCIC:STIX_Package-c6e42472-0055-4d55-ac9a-67af9ec39bb9
	#      becomes c6e42472-0055-4d55-ac9a-67af9ec39bb9
	uuid_ = pkg.id_.split('-', 1)[1]
	# uuid needs to match /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/
	# If it isn't well-formed, we'll generate a new one based on the package id
	if not re.match('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$', uuid_):
		uuid_ = uuid.uuid5(uuid.NAMESPACE_OID, pkg.id_)
	print("UUID: ", uuid_)
	# Extract the header from the package
	header = pkg.stix_header
	print("Title:", header.title)

	# "attributes" holds all the MISP attributes (e.g. the indicators
	# for the MISP event.
	attributes = []

	# Create a dictionary to map objects to their ids so we can
	# dereference them later.
	deref = {}
	if pkg.observables:
		for observable in pkg.observables:
			object_ = observable.object_
			deref[object_.id_] = object_

	# Run through the list of STIX Indicators
	if pkg.indicators:
		# Parse all the Observables from the Indicators
		# and create MISP attributes from them
		for indicator in pkg.indicators:
			print(" ", indicator.id_)
			print(" ", indicator.description)
			print(" ", indicator.title)
			observable = indicator.observable
			if not observable:
				print("Indicator", indicator.id_, "has no observable")
				continue
			if indicator.observable.object_.idref:
				if indicator.observable.object_.idref in deref:
					object_ = deref[indicator.observable.object_.idref]
				else:
					print("Indicator", indicator.id_, "references observable object", indicator.observable.object_.idref + ", which does not exist")
					raise AttributeError("Indicator references a non-existent object")
			else:
				object_ = observable.object_
			if indicator.timestamp:
				ts = indicator.timestamp.strftime('%s')
			else:
				ts = None
			attributes = attributes + create_attributes(
				object_,
				misp_comment=str(indicator.description),
				indicator_timestamp=ts,
				deref=deref
			)

	# CISCP STIX documents have observables that aren't tied to any indicators.
	# Create MISP attributes for them here.
	#
	# This is actually kludgey.  For MIFRs, objects may be referenced from TTPs
	# rather than Indicators.  To do this correctly, we really should parse TTPs.
	for idref in list(deref.keys()):
		# Each time create_attributes is called, it removes the key from
		# the deref dict.  That prevents us from duplicating objects or
		# recursing infinitely due to circular relations.
		if idref in deref:
			object_ = deref[idref]
			attributes = attributes + create_attributes(
				object_,
				deref=deref
			)

	# Remove duplicate attributes
	uniq = {}
	uniq_attributes = []
	for attribute in attributes:
		if attribute['value'] not in uniq:
			uniq_attributes.append(attribute)
			uniq[attribute['value']] = True

	# Return the attributes and the MISP Event object structure
	return uniq_attributes, {
		'uuid'            : str(uuid_),
                'published'       : 1,
                'info'            : pkg.id_,
                'analysis'        : 2,
                'timestamp'       : pkg.timestamp.strftime('%s'),
                'Attribute'       : uniq_attributes,
		'SharingGroup'    : {},
		'Tag'             : []
	}


# Create the event in MISP via the API
def create_misp_event(misp_url, misp_key, event, verify_cert=True):
	headers = {
		'Authorization' : misp_key,
		'Content-Type'  : 'application/json',
		'Accept'        : 'application/json'
	}
	response = requests.post(misp_url + '/events', headers=headers, data=json.dumps({ 'Event' :  event}), verify=verify_cert)
	print(response.text)
	return(response)

if __name__ == "__main__":
	# Parse the command line arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("input_file", help="An AIS or CISCP XML STIX Package file")
	parser.add_argument("-u", "--misp-url", help="MISP server URL (default to https://localhost)", default="https://localhost")
	parser.add_argument("-k", "--misp-key", help="MISP API key", required=True)
	parser.add_argument("-v", "--verify-cert", help="Verify TLS certificate (defaults to true)", default="yes")
	parser.add_argument("-d", "--distribution", help="MISP Event distribution (org, community, connected, all, or a sharing group UUID)", default="org")
	parser.add_argument("-t", "--tags", help="MISP Event tags (use multiple times to set more than one tag)", action="append")
	parser.add_argument("-l", "--level", help="MISP threat level (high, medium, low, or undefined - defaults to low)", default="low")
	args = parser.parse_args()

	# Set the event distribution.
	# "org" means the event is only visible to your own org
	# "community" means the event is visible to anyone who can log into your MISP
	# "connected" shares with all connected MISP instances
	# "all" shares with connected instances and instances connected to them
	# A sharing group UUID will share based on the sharing group's settings
	# The MISP UI doesn't expose sharing group UUIDs, so you have to use the DB.
	# mysql> select name, uuid from misp.sharing_groups;
	sharing_group_uuid = None
	if args.distribution in ["0", "1", "2", "3", "4"]:
		distribution = int(args.distribution)
	elif args.distribution == "org":
		distribution = 0
	elif args.distribution == "community":
		distribution = 1
	elif args.distribution == "connected":
		distribution = 2
	elif args.distribution == "all":
		distribution = 3
	elif re.match('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$', args.distribution):
		distribution = 4
		sharing_group_uuid = args.distribution
	else:
		raise ValueError("Distribution must be 'org', 'community', 'connected', 'all', or a sharing group UUID")

	# Turn the --verify-cert arg into a bool
	if args.verify_cert.lower() in ('yes', 'true', 't', 'y', '1'):
		args.verify_cert = True
	elif args.verify_cert.lower() in ('no', 'false', 'f', 'n', '0'):
		args.verify_cert = False
	else:
		raise argparse.ArgumentTypeError('Boolean value expected for --verify-cert')

	# Set the threat level id.  Defaults to low.
	if args.level in ["1", "2", "3", "4"]:
		threat_level_id = int(args.level)
	elif args.level == "high":
		threat_level_id = 1
	elif args.level == "medium":
		threat_level_id = 2
	elif args.level == "low":
		threat_level_id = 3
	elif args.level == "undefined":
		threat_level_id = 4
	else:
		raise ValueError("Threat level must be 'high', 'medium', 'low', or 'undefined'")
	
	# Load the input file, parse it, and generate a MISP event with attributes
	attributes, event = parse_package(args.input_file)

	# Each MISP event gets a comment attribute
	# with the input file name as its value
	event['Attribute'].append({
		'category'     : 'Other',
		'type'         : 'comment',
		'value'        : args.input_file,
		'to_ids'       : 0,
		'distribution' : 5
	})

	# Set the distribution and threat level
	event['distribution']    = distribution
	event['threat_level_id'] = threat_level_id

	# If we were given a sharing group uuid as the distribution arg,
	# add it here.
	if sharing_group_uuid:
		event['SharingGroup']['uuid'] = sharing_group_uuid

	# If we were given a tag, add it here
	for tag_name in args.tags:
		event['Tag'].append({ 'name' : tag_name })
		
	# Output the complete event with all attributes
	print(json.dumps(event, indent=1))

	# Create the event on the MISP server
	response = create_misp_event(args.misp_url, args.misp_key, event, args.verify_cert)
	response_dict = response.json()
	if 'errors' in response_dict:
		print("Errors:", json.dumps(response_dict['errors'], indent=1))
		for index in response_dict['errors']['Attribute'].keys():
			print("Error:", attributes[int(index)])
		sys.exit(1)
