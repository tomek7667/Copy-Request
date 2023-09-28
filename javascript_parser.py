class JavascriptParser():
	def __init__(self, stdout, stderr):
		print("JavascriptParser init")
		self.stdout = stdout
		self.stderr = stderr

	def parse(self, data):
		print('parse: data', data)