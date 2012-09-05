from filter import Filter

class SledFilter:
	def __init__(self, targets, period):
		self._dp_filter = Filter(targets, period, self._dp_callback)
		self._src_filter = Filter(targets, period, self._src_callback)

	def _dp_callback(self, key):
		pass

	def _src_callback(self, key):
		pass

	def process(self, sled):
		self._dp_filter.process(
			sled.get_dp(), sled.get_dst(), sled.get_timestamp())
		self._src_filter.process(
			sled.get_src(), sled.get_dst(), sled.get_timestamp())
