import os
import popen2
import signal
import gobject

from messages import *



def mask(bits):
	return hex((2**long(bits)-1)<<(32-bits))
	# [:-1] if we would like to remove trailing L


class Monitor:
	def __init__(self, config, handler):
		self._config = config
		self._handler = handler

	def start(self):
		s = ""
		if self._config.getboolean("monitor", "skipnul"):
			s = s + " --skip-nul"

		if self._config.getboolean("monitor", "enable_stride"):
			s = s + " --enable-stride"
			
		cmdline = "./ear.sh%s --stride-flow-depth=%d --stride-sled-length=%d -f %d -p %d -s %s -t %d -l %d -n %s %s" % (
			s,
			self._config.getint("monitor", "max_sled_offset"),
			self._config.getint("monitor", "min_sled_length"),
			self._config.getint("monitor", "offset"),
			self._config.getint("monitor", "memory"),
			mask(self._config.getint("monitor", "mask")),
			self._config.getint("monitor", "targets"),
			self._config.getint("monitor", "length"),
			self._config.get("monitor", "homenet"),
			self._config.get("monitor", "filter"),
		)

		print "Executing: ", cmdline

		self._slave = popen2.Popen3(cmdline)

		self._source_id = gobject.io_add_watch(self._slave.fromchild,
			gobject.IO_IN, self._input_callback)

	def _input_callback(self, source, condition):
		message = MessageParser().parse(self._slave.fromchild)
		message.dispatch(self._handler)
		return True

	def restart(self):
		self.stop()
		self.start()

	def stop(self):
		gobject.source_remove(self._source_id)
		os.kill(self._slave.pid, signal.SIGTERM)
		self._slave.wait()
