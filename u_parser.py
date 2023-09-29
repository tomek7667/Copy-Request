import random
import string
from common import *

class Parser:
	def getFirstHeaderInfo(self, raw_data):
		record = raw_data.split('\n\n')[0].split('\n')[0]
		[method, _, version] = record.split(' ')
		return {
			'method': method,
			'version': version
		}

	def randomString(self, length=4):
		return ''.join(random.choice(string.ascii_letters) for _ in range(length))
