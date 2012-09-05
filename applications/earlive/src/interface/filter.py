class Filter:

	def __init__(self, targets_threshold, period, callback):
		self._keys = {}

		self._targets_threshold = targets_threshold
		self._period = period
		self._callback = callback
		self._queue = []
		self._keys = {}
		self._reported = {}

	def _expire(self, current_time):
		while len(self._queue) > 0:
			(key, target, time) = self._queue[-1]
			if time >= current_time - self._period: break

			self._queue.pop()

			if self._keys[key][target] == time:
				del self._keys[key][target]
			if len(self._keys[key]) == 0:
				del self._keys[key]

	def process(self, key, target, current_time):
		self._expire(current_time)
		
		if key in self._reported:
			return

		if not self._keys.has_key(key):
			self._keys[key] = {}
		self._keys[key][target] = current_time
		self._queue.insert(0, (key, target, current_time))

		# report entry if reached threshold
		if len(self._keys[key]) >= self._targets_threshold:
			self._reported[key] = None
			self._callback(key)

	def forget(self, key):
		del self._reported[key]

def callback(key):
	print key

def test:
	#
	print('-----')
	f = Filter(3, 10, callback)
	f.process('b', 'xxx', 0.0)
	f.process('b', 'xxx', 0.0)
	f.process('b', 'xxx', 0.0)

	# 
	print('-----')
	f = Filter(3, 10, callback)
	f.process('b', 'xxx', 0.0)
	f.process('b', 'yyy', 0.0)
	f.process('b', 'zzz', 0.0)


	# 
	print('-----')
	f = Filter(3, 10, callback)
	f.process('b', 'xxx', 0.0)
	f.process('b', 'yyy', 50.0)
	f.process('b', 'zzz', 50.0)

	# 
	print('-----')
	f = Filter(3, 10, callback)
	f.process('b', 'xxx', 0.0)
	f.process('b', 'yyy', 0.0)
	f.process('b', 'zzz', 0.0)
	f.process('b', 'xxx2', 0.0)
	f.process('b', 'yyy2', 0.0)
	f.process('b', 'zzz2', 0.0)





