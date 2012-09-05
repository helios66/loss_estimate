#!/usr/bin/python

import pygtk
pygtk.require('2.0')
import gtk
import sys, time
import re
import ConfigParser

from monitor import Monitor
from gui import EarGUI

class Main:
	def __init__(self):
		self._cputime = 0
		self._walltime = 0
		self.load_config()
		self._gui = EarGUI(self)
		self._monitor = Monitor(self.config, self)
		self.start_monitor()
		gtk.main()

	def load_config(self):
		defaults = {
			'targets':'10',
			'length':'300',
			'offset':'10000',
			'memory':'500',
			'filter':'',
			'homenet':'',
			'mask':'4',
			'skipnul':'0',
			'sources':'1',
			'contagion':'0',

			'enable_stride':'1',
			'min_sled_length':'160',
			'max_sled_offset':'2000',
		}
		self.config = ConfigParser.ConfigParser(defaults)
		self.config.read("ear.conf")
		if not self.config.has_section("monitor"):
			self.config.add_section("monitor")

	def save_config(self):				
		f = open("ear.conf", "w")
		self.config.write(f)
		f.close()

	def restart_monitor(self):
		self._gui.clear_alerts()
		self._monitor.restart()

	def stop_monitor(self):
		self._monitor.stop()


	def start_monitor(self):
		self._monitor.start()

	def check_alert(self, alert):
		return (alert.get_source_count() >= self.config.getint("monitor", "sources") and
			alert.get_contagion() >= self.config.getint("monitor", "contagion"))
	
	def process_alert_message(self, alert):
		if self.check_alert(alert):
			self._gui.show_alert(alert)

	def process_tracked_message(self, tracked):
		# XXX Hash may not exist in GUI
		self._gui.show_tracked(tracked)

	def process_sled_message(self, sled):
		self._gui.show_sled(sled)

	def process_status_message(self, status):
		avg = status.get('avg_usage')
		avg_rounded = str(float(int(float(avg)*100))/100)

		cputime = float(status.get('elapsed_cpu_time'))
		walltime = float(status.get('elapsed_wallclock_time'))
		dcputime =  (cputime - self._cputime)
		dwalltime = (walltime - self._walltime)
		if dwalltime > 0:
			utilization = str(int(10000*(dcputime / dwalltime))/100)
		else:
			utilization = "N/A"

		self._cputime = cputime
		self._walltime = walltime
	
		dict = {}
		dict['last_update'] = time.ctime(float(status.get('timestamp')))
		dict['cur_usage'] = status.get('cur_usage')
		dict['max_usage'] = status.get('max_usage')
		dict['avg_usage'] = avg_rounded
		dict['utilization'] = utilization + "%"

		self._gui.set_status(dict)

	def set_config(self, dict):
		self.config.set("monitor", "targets", dict['targets'])
		self.config.set("monitor", "length", dict['length'])
		self.config.set("monitor", "offset", dict['offset'])
		self.config.set("monitor", "memory", dict['memory'])
		self.config.set("monitor", "filter", dict['filter'])
		self.config.set("monitor", "homenet", dict['homenet'])
		self.config.set("monitor", "skipnul", dict['skipnul'])
		self.config.set("monitor", "sources", dict['sources'])
		self.config.set("monitor", "contagion", dict['contagion'])
		self.config.set("monitor", "mask", dict['mask'])

		self.config.set("monitor", "enable_stride",
			dict['enable_stride'])
		self.config.set("monitor", "min_sled_length",
			dict['min_sled_length'])
		self.config.set("monitor", "max_sled_offset",
			dict['max_sled_offset'])

		self.save_config()
		self.restart_monitor()

	def get_config(self):
		dict = {}
		dict['targets'] = self.config.getfloat("monitor", "targets")
		dict['length'] = self.config.getfloat("monitor", "length")
		dict['offset'] = self.config.getfloat("monitor", "offset")
		dict['memory'] = self.config.getfloat("monitor", "memory")
		dict['filter'] = self.config.get("monitor", "filter")
		dict['homenet'] = self.config.get("monitor", "homenet")
		dict['skipnul'] = self.config.getboolean("monitor", "skipnul")
		dict['sources'] = self.config.getfloat("monitor", "sources")
		dict['contagion'] = self.config.getfloat("monitor", "contagion")
		dict['mask'] = self.config.getfloat("monitor", "mask")
		dict['enable_stride'] = self.config.getboolean("monitor", "enable_stride")
		dict['min_sled_length'] = self.config.getfloat("monitor", "min_sled_length")
		dict['max_sled_offset'] = self.config.getfloat("monitor", "max_sled_offset")

		return dict

	def shutdown(self):
		gtk.main_quit()
		self.stop_monitor()

Main()
