import pygtk
pygtk.require('2.0')
import gtk, gtk.glade, pango

class EarGUI:
	def __init__(self, callback):
		self._callback = callback
		self.alerts = {}
		self.build_gui()

	def build_gui(self):
		xml = gtk.glade.XML('ear.glade', 'window1')
		xml.signal_autoconnect(self)
		self.get_widget = xml.get_widget

		self.substring_textview = xml.get_widget('textview1')
		self.alert_treeview = xml.get_widget('treeview1')
		self.notebook1 = xml.get_widget('notebook1')
		self.connections_treeview = xml.get_widget('treeview2')
		self.tracked_treeview = xml.get_widget('treeview4')
		self.sled_treeview = xml.get_widget('treeview3')
		
		self._build_alert_treeview()
		self._build_sled_treeview()
		self._build_tracked_treeview()
		self._build_connections_treeview()
		self._build_substring_textview()


	def _build_substring_textview(self):
		font_desc = pango.FontDescription('monospace')
		self.substring_textview.modify_font(font_desc)

	def _build_connections_treeview(self):
		column = gtk.TreeViewColumn('Source IP',
			gtk.CellRendererText(), text=0)
		self.connections_treeview.append_column(column)
		column = gtk.TreeViewColumn('Source Port',
			gtk.CellRendererText(), text=1)
		self.connections_treeview.append_column(column)
		column = gtk.TreeViewColumn('Destination IP',
			gtk.CellRendererText(), text=2)
		self.connections_treeview.append_column(column)
		column = gtk.TreeViewColumn('Destination Port',
			gtk.CellRendererText(), text=3)
		self.connections_treeview.append_column(column)
		column = gtk.TreeViewColumn('Substring Offset',
			gtk.CellRendererText(), text=4)
		self.connections_treeview.append_column(column)
		column = gtk.TreeViewColumn('Timestamp',
			gtk.CellRendererText(), text=5)
		self.connections_treeview.append_column(column)

		liststore = gtk.ListStore(str, str, str, str, str, str)
		self.connections_treeview.set_model(liststore)

		self.connections_treeview.get_selection().set_mode(gtk.SELECTION_NONE)

		font_desc = pango.FontDescription('monospace')
		self.connections_treeview.modify_font(font_desc)


	def _build_tracked_treeview(self):
		column = gtk.TreeViewColumn('Source IP',
			gtk.CellRendererText(), text=0)
		self.tracked_treeview.append_column(column)
		column = gtk.TreeViewColumn('Source Port',
			gtk.CellRendererText(), text=1)
		self.tracked_treeview.append_column(column)
		column = gtk.TreeViewColumn('Destination IP',
			gtk.CellRendererText(), text=2)
		self.tracked_treeview.append_column(column)
		column = gtk.TreeViewColumn('Destination Port',
			gtk.CellRendererText(), text=3)
		self.tracked_treeview.append_column(column)
		column = gtk.TreeViewColumn('Substring Offset',
			gtk.CellRendererText(), text=4)
		self.tracked_treeview.append_column(column)
		column = gtk.TreeViewColumn('Timestamp',
			gtk.CellRendererText(), text=5)
		self.tracked_treeview.append_column(column)

		liststore = gtk.ListStore(str, str, str, str, str, str)
		self.tracked_treeview.set_model(liststore)

		self.tracked_treeview.get_selection().set_mode(gtk.SELECTION_NONE)

		font_desc = pango.FontDescription('monospace')
		self.tracked_treeview.modify_font(font_desc)




	def _build_sled_treeview(self):
		column = gtk.TreeViewColumn('Timestamp',
			gtk.CellRendererText(), text=0)
		self.sled_treeview.append_column(column)

		column = gtk.TreeViewColumn('Source',
			gtk.CellRendererText(), text=1)
		self.sled_treeview.append_column(column)
		column = gtk.TreeViewColumn('Source Port',
			gtk.CellRendererText(), text=2)
		self.sled_treeview.append_column(column)
		column = gtk.TreeViewColumn('Dest.',
			gtk.CellRendererText(), text=3)
		self.sled_treeview.append_column(column)
		column = gtk.TreeViewColumn('Dest. Port',
			gtk.CellRendererText(), text=4)
		self.sled_treeview.append_column(column)
		liststore = gtk.ListStore(str, str, str, str, str)
		self.sled_treeview.set_model(liststore)
		self.sled_treeview.get_selection().set_mode(gtk.SELECTION_NONE)

		font_desc = pango.FontDescription('monospace')
		self.sled_treeview.modify_font(font_desc)

	def _build_alert_treeview(self):
		self.alert_treeview.get_selection().connect('changed',
			self.on_selection_changed)

		column = gtk.TreeViewColumn('Substring Hash',
			gtk.CellRendererText(), text=0)
		self.alert_treeview.append_column(column)

		column = gtk.TreeViewColumn('Alert Time',
			gtk.CellRendererText(), text=1)
		self.alert_treeview.append_column(column)

		column = gtk.TreeViewColumn('Sources',
			gtk.CellRendererText(), text=2)
		self.alert_treeview.append_column(column)

		column = gtk.TreeViewColumn('Destinations',
			gtk.CellRendererText(), text=3)
		self.alert_treeview.append_column(column)

		column = gtk.TreeViewColumn('Contagion',
			gtk.CellRendererText(), text=4)
		self.alert_treeview.append_column(column)

		liststore = gtk.ListStore(str, str, int, int, int)
		self.alert_treeview.set_model(liststore)

		font_desc = pango.FontDescription('monospace')
		self.alert_treeview.modify_font(font_desc)


	def clear_alerts(self):
		self.alerts = {}
		self.alert_treeview.get_model().clear()
		self.sled_treeview.get_model().clear()

	def show_tracked(self, tracked):
		if self.alerts.has_key(tracked.get_hash()):
			alert = self.alerts[tracked.get_hash()]
			alert.add_tracked(tracked)

	def show_alert(self, alert):
		self.alerts[alert.get_hash()] = alert
		self.alert_treeview.get_model().append([
			alert.get_hash(),
			alert.get_time(),
			alert.get_source_count(),
			alert.get_target_count(),
			alert.get_contagion(),
		])

	def show_sled(self, sled):
		self.sled_treeview.get_model().append([
			sled.get_timestamp(),
			sled.get_src(),
			sled.get_sp(),
			sled.get_dst(),
			sled.get_dp(),
		])

	def set_status(self, dict):
		self.get_widget('last_update').set_text(dict['last_update'])
		self.get_widget('cur_usage').set_text(dict['cur_usage'])
		self.get_widget('max_usage').set_text(dict['max_usage'])
		self.get_widget('avg_usage').set_text(dict['avg_usage'])
		self.get_widget('utilization').set_text(dict['utilization'])
	
	def on_selection_changed(self, treeselection):
		(model, iter) = treeselection.get_selected()
		self.notebook1.set_sensitive(iter != None)

		if iter != None:
			hash = model.get_value(iter, 0)
			alert = self.alerts[hash]
		else:
			alert = NullAlert

		self.substring_textview.get_buffer().set_text(alert.get_substring())
		self.connections_treeview.get_model().clear()
		for conn in alert.get_connections():
			self.connections_treeview.get_model().append(conn)

		self.tracked_treeview.get_model().clear()
		for tracked in alert.get_tracked():
			self.tracked_treeview.get_model().append(tracked)

	def on_window1_destroy(self, window):
		self._callback.shutdown()

	def on_quit1_activate(self, widget):
		self._callback.shutdown()

	def on_about1_activate(self, widget):
		xml = gtk.glade.XML('ear.glade', 'dialog2')
		dialog2 = xml.get_widget('dialog2')
		dialog2.run()
		dialog2.destroy()

	def on_configure_activate(self, widget):
		xml = gtk.glade.XML('ear.glade', 'dialog1')
		dialog1 = xml.get_widget('dialog1')

		dict = self._callback.get_config()

		spinbutton1 = xml.get_widget('spinbutton1')
		spinbutton1.set_value(dict['targets'])
		spinbutton2 = xml.get_widget('spinbutton2')
		spinbutton2.set_value(dict['length'])
		spinbutton3 = xml.get_widget('spinbutton3')
		spinbutton3.set_value(dict['offset'])
		spinbutton4 = xml.get_widget('spinbutton4')
		spinbutton4.set_value(dict['memory'])
		entry1 = xml.get_widget('entry1')
		entry1.set_text(dict['filter'])
		entry2 = xml.get_widget('entry2')
		entry2.set_text(dict['homenet'])
		checkbutton1 = xml.get_widget('checkbutton1')
		checkbutton1.set_active(dict['skipnul'])
		spinbutton5 = xml.get_widget('spinbutton5')
		spinbutton5.set_value(dict['sources'])
		spinbutton6 = xml.get_widget('spinbutton6')
		spinbutton6.set_value(dict['contagion'])
		spinbutton7 = xml.get_widget('spinbutton7')
		spinbutton7.set_value(dict['mask'])
		checkbutton2 = xml.get_widget('checkbutton2')
		checkbutton2.set_active(dict['enable_stride'])
		spinbutton8 = xml.get_widget('spinbutton8')
		spinbutton8.set_value(dict['min_sled_length'])
		spinbutton9 = xml.get_widget('spinbutton9')
		spinbutton9.set_value(dict['max_sled_offset'])

		response = dialog1.run()
		if response == gtk.RESPONSE_OK:
			# retrieve new options
			dict = {}
			dict['targets'] = str(spinbutton1.get_value_as_int())
			dict['length'] = str(spinbutton2.get_value_as_int())
			dict['offset'] = str(spinbutton3.get_value_as_int())
			dict['memory'] = str(spinbutton4.get_value_as_int())
			dict['filter'] = str(entry1.get_text())
			dict['homenet'] = str(entry2.get_text())
			dict['skipnul'] = str(checkbutton1.get_active())
			dict['sources'] = str(spinbutton5.get_value_as_int())
			dict['contagion'] = str(spinbutton6.get_value_as_int())
			dict['mask'] = str(spinbutton7.get_value_as_int())

			dict['enable_stride'] = str(checkbutton2.get_active())
			dict['min_sled_length'] = str(spinbutton8.get_value_as_int())
			dict['max_sled_offset'] = str(spinbutton9.get_value_as_int())

			self._callback.set_config(dict)
			
		dialog1.destroy()
