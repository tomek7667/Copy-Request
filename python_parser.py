class PythonParser():
	def __init__(self, stdout, stderr):
		print("PythonParser init")
		self.stdout = stdout
		self.stderr = stderr

	def parse(self, data):
		print('parse: data', data)
