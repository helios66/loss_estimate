
dist_sysconf_DATA = \
ear_monitor.conf \
ear_out_parser.awk

install-data-hook:
	echo "# earlive directory. this directory containts earlive's web interface" >> $(sysconfdir)/ear_monitor.conf
	echo "# files. this option is added automatically at install time and should" >> $(sysconfdir)/ear_monitor.conf
	echo "# not be changed by hand." >> $(sysconfdir)/ear_monitor.conf
	echo "earlivedir=\"$(WWW_DIR)\"" >> $(sysconfdir)/ear_monitor.conf
