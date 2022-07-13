#!/usr/bin/env python
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
# Copyright (c) WorNet AG 2022
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description: Drop-In Replacement for old wmic lib on linux systems
# 
# Author:
#  Alberto Solino (@agsolino)
#  Andreas Erhard (WorNet AG)
# -- ref https://github.com/CoreSecurity/impacket/blob/master/examples/wmiquery.py
# -- ref https://github.com/SecureAuthCorp/impacket/blob/master/LICENSE

# added -A switch by maldex, 13.7.2022

import argparse
import sys
import os
import logging
import re

from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection


if __name__ == '__main__':
	import cmd
	
	parser = argparse.ArgumentParser(add_help = True, description = "Executes WQL queries and gets object descriptions using Windows Management Instrumentation.")
	parser.add_argument('-U', '--username', action='store', help='The domain, username andpassword of the remote Windows account. Example: [domain/]adminuser%password')
	parser.add_argument('-A', '--authentication-file', dest='authfile', help="Authentication file")
	parser.add_argument('-v', '--verbose', action='store_true', help='Print extra debug information. Don\'t include this in your check_command definition!', default=False)
	parser.add_argument('-n', '--namespace', action='store', help='The WMI namespace to use for the query.', default='root/cimv2')
	parser.add_argument('host', action='store', help='The host name or logical address of the remote Windows machine. Example: //127.0.0.1');
	parser.add_argument('query', action='store', help='The wmic query string');
	
	args = parser.parse_args()
	host = args.host.split('//',1)[1]

	if args.authfile is not None:
		for line in open(args.authfile,'r').readlines():
			if line.startswith("domain="): domain = line.split('=')[-1].strip()
			if line.startswith("username="): username = line.split('=')[-1].strip()
			if line.startswith("password="): password = line.split('=')[-1].strip()

	elif args.username is not None:
		domain, username, password = re.compile('(?:(?:([^/\\\\%]*)[/\\\\])?([^%]*))(?:%(.*))?').match(args.username).groups('')
	else:
		print("Missing user information")
		sys.exit(1)


	class WMIQUERY(cmd.Cmd):
		def __init__(self, iWbemServices):
			cmd.Cmd.__init__(self)
			self.iWbemServices = iWbemServices
			self.prompt = 'WQL> '
			self.intro = '[!] Press help for extra shell commands'

		def do_help(self, line):
			print('''
	 lcd {path}					- changes the current local directory to {path}
	 exit						- terminates the server process (and this session)
	 describe {class}			- describes class
	 ! {cmd}					- executes a local shell cmd
	 ''')

		def do_shell(self, s):
			os.system(s)

		def do_describe(self, sClass):
			sClass = sClass.strip('\n')
			if sClass[-1:] == ';':
				sClass = sClass[:-1]
			try:
				iObject, _ = self.iWbemServices.GetObject(sClass)
				iObject.printInformation()
				iObject.RemRelease()
			except Exception as e:
				#import traceback
				#print traceback.print_exc()
				logging.error(str(e))

		def do_lcd(self, s):
			if s == '':
				print(os.getcwd())
			else:
				os.chdir(s)
	
		def printReply(self, iEnum):
			printHeader = True
			while True:
				try:
					pEnum = iEnum.Next(0xffffffff,1)[0]
					record = pEnum.getProperties()
					if printHeader is True:
						wmiClass = re.split('from', args.query, flags=re.IGNORECASE)[1].split(' ',2)[1]
						print('CLASS: ' + wmiClass)

						first = True
						for col in record:
							if not first:
								sys.stdout.write('|')
							else:
								first = False
							sys.stdout.write(col)
						print('')
						printHeader = False
					first = True
					for key in record:
						if not first:
							sys.stdout.write('|')
						else:
							first = False
						sys.stdout.write(str(record[key]['value']))
					print ('')
				except Exception as e:
					#import traceback
					#print traceback.print_exc()
					if str(e).find('S_FALSE') < 0:
						raise
					else:
						break

		def default(self, line):
			line = line.strip('\n')
			if line[-1:] == ';':
				line = line[:-1]
			try:
				iEnumWbemClassObject = self.iWbemServices.ExecQuery(line.strip('\n'))
				self.printReply(iEnumWbemClassObject)
				iEnumWbemClassObject.RemRelease()

			except Exception as e:
				logging.error(str(e))
		 
		def emptyline(self):
			pass

		def do_exit(self, line):
			return True

	try:
		dcom = DCOMConnection(host, username, password, domain, "", "", "", oxidResolver=True,doKerberos=False, kdcHost="")

		iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login,wmi.IID_IWbemLevel1Login)
		iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
		iWbemServices = iWbemLevel1Login.NTLMLogin("//./" + args.namespace, NULL, NULL)

		iWbemLevel1Login.RemRelease()
		shell = WMIQUERY(iWbemServices)

		shell.onecmd(args.query)
		iWbemServices.RemRelease()
		dcom.disconnect()
		exit(0)
		
	except Exception as e:
		logging.error(str(e))
		try:
			dcom.disconnect()
		except:
			pass
