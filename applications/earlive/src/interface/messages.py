import re
import time


def uniq(items):
    d = {}
    for item in items:
        d[item]=1
    return d.keys()

# Unused
class Connection:
	def __init__(self, src, sp, dst, dp, offset, timestamp):
		self._src = src
		self._sp = sp
		self._dst = dst
		self._dp = dp
		self._offset = offset
		self._timestamp = timestamp

class Conn:
	def __init__(self, s):
		self._connections = []
		self._sources = []
		self._destinations = []
		self._tracked = []

		for line in s.split('\n'):
			if line == '': continue
			# TODO handle N/A correctly: \d+ won't match it
			(src, sp, dst, dp, offset, timestamp) = re.match(
				r"(\S+):(\S+) -> (\S+):(\S+) offset: (\d+) timestamp: (\d+\.\d+)", line).groups()

			self._connections.append( (src, sp, dst, dp, offset, timestamp) )
			self._sources.append(src)
			self._destinations.append(dst)

	def get_connections(self):
		return self._connections

	def get_contagion(self):
		result = 0
		for source in uniq(self._sources):
			for dest in self._destinations:
				if source == dest:
					result = result + 1
		return result

	def get_source_count(self):
		return len(uniq(self._sources))

	def get_target_count(self):
		return len(uniq(self._destinations))

	def add_tracked(self, tracked):
		(src, sp, dst, dp, offset, timestamp) = tracked
		self._sources.append(src)
		self._destinations.append(dst)
		self._tracked.append(tracked)

	def get_tracked(self):
		return self._tracked

class SledMessage:
	def __init__(self, timestamp, src, sp, dst, dp):
		self._timestamp = timestamp
		self._src = src
		self._sp = sp
		self._dst = dst
		self._dp = dp

	def dispatch(self, handler):
		handler.process_sled_message(self)

	def get_timestamp(self):
		return self._timestamp

	def get_time(self):
		return time.ctime(float(self._timestamp))

	def get_src(self):
		return self._src

	def get_sp(self):
		return self._sp

	def get_dst(self):
		return self._dst

	def get_dp(self):
		return self._dp

class Tracked:
	def __init__(self, hash, offset, timestamp, src, sp, dst, dp):
		self._hash = hash
		self._offset = offset
		self._timestamp = timestamp
		self._src = src
		self._sp = sp
		self._dst = dst
		self._dp = dp

	def dispatch(self, handler):
		handler.process_tracked_message(self)

	def get_hash(self):
		return self._hash

	def get_offset(self):
		return self._offset

	def get_timestamp(self):
		return self._timestamp

	def get_src(self):
		return self._src

	def get_sp(self):
		return self._sp

	def get_dst(self):
		return self._dst

	def get_dp(self):
		return self._dp


class Alert:
	def __init__(self, hash, timestamp, substring, connections):
		self._hash = hash
		self._timestamp = timestamp
		self._substring = substring
		self._connections = Conn(connections)
		self._tracked = []

	def get_hash(self):
		return self._hash

	def get_timestamp(self):
		return self._timestamp

	def get_time(self):
		return time.ctime(float(self._timestamp))

	def get_connections(self):
		return self._connections.get_connections()

	def get_substring(self):
		return self._substring

	def get_source_count(self):
		return self._connections.get_source_count()

	def get_target_count(self):
		return self._connections.get_target_count()


	def get_contagion(self):
		return self._connections.get_contagion()

	def dispatch(self, handler):
		handler.process_alert_message(self)

	def add_tracked(self, tracked):
		self._connections.add_tracked((
			tracked.get_src(),
			tracked.get_sp(),
			tracked.get_dst(),
			tracked.get_dp(),
			tracked.get_offset(),
			tracked.get_timestamp(),
		))

	def get_tracked(self):
		return self._connections.get_tracked()

NullAlert = Alert("", "", "", "")

class StatusMessage:
	def __init__(self, dict):
		self._dict = dict
		self.get = dict.get

	def dispatch(self, handler):
		handler.process_status_message(self)


class MessageParser:
	def _read_block(self, f):
		result = ""
		while 1:
			line = f.readline()
			if line == "\n" or line == "": break
			else: result = result + line
		return result

	def parse(self, f):
		line = f.readline()
		while line != '':

			if line == "ALERT\n":
				return self._parse_alert(f)
			if line == "TRACKED\n":
				return self._parse_tracked(f)
			elif line == "STATUS\n":
				return self._parse_status(f)
			elif line == "SUMMARY\n":
				# XXX unimplemented
				pass
			elif line == "SLED\n":
				return self._parse_sled(f)

			line = f.readline()

	def _parse_alert(self, f):
		line = f.readline()
		(hash, timestamp, positive) = line.split()
		substring = self._read_block(f)
		connections = self._read_block(f)
		return Alert(hash, timestamp, substring, connections)

	def _parse_tracked(self, f):
		line = f.readline()
		(hash, offset, timestamp, src, sp, dst, dp) = re.match(r"(.*) (.*) (.*) (.*):(.*) -> (.*):(.*)", line).groups()
		return Tracked(hash, offset, timestamp, src, sp, dst, dp)

	def _parse_sled(self, f):
		timestamp = f.readline()[:-1]
		line = f.readline()
		(src, sp, dst, dp) = re.match(r"(.*):(.*) -> (.*):(.*)", line).groups()
		return SledMessage(timestamp, src, sp, dst, dp)



	def _parse_status(self, f):
		dict = {}
		while 1:
			line = f.readline()
			if line == "\n": break
			(key, data) = re.match(r"(\S+): (.*)", line).groups()
			dict[key] = data
			#print "%s -> %s\n" % (key, data)
		return StatusMessage(dict)
