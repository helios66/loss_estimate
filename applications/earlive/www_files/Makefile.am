wwwdir = $(WWW_DIR)

dist_www_DATA = \
alerts.php report.php \
data.php showAlert.php \
stylesheet.css \
earlive-0.2.jar \
jchart2d-2.0.1.jar \
index.html

install-data-hook:
	mkdir -p "$(wwwdir)alerts"
	test -p "$(wwwdir)comm" || mkfifo -m 777 "$(wwwdir)comm" 
