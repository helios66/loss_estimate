confdir = $(sysconfdir)/mapi
conf_DATA = mapi.conf 

# override the default conf install to check for mapi.conf overwrite
install-confDATA: $(conf_DATA)
	@$(NORMAL_INSTALL)
	@test -z "$(confdir)" || mkdir -p "$(DESTDIR)$(confdir)"
	@list='$(conf_DATA)'; for p in $$list; do \
		if test -f $$p; then \
			if test -e "$(DESTDIR)$(confdir)/$$p"; then \
				echo -e "\nConfig file $$p already exists in $(DESTDIR)$(confdir) - not overwriting...\n"; \
			else \
				echo " $(INSTALL) -m 644 $$p $(DESTDIR)$(confdir)/$$f"; \
				$(INSTALL) -m 644 $$p $(DESTDIR)$(confdir)/$$f; \
			fi \
		fi \
	done
if BINARY_DAGFLIB
	$(INSTALL) -m 755 dag_ipf_loader.sh.example $(DESTDIR)$(sbindir)
endif

install-data-local:
# ssl stuff
if SSL_IS_ENABLED
	echo "Generating SSL keys"
	openssl genrsa -out mapicommd_key.pem 1024 2> /dev/null
	openssl req -new -x509 -days 30000 -key mapicommd_key.pem -out mapicommd_cert.pem -config mapicommd_cert.cnf
	${INSTALL} -m 600 mapicommd_key.pem $(DESTDIR)$(confdir)/mapicommd_key.pem
	${INSTALL} -m 600 mapicommd_cert.pem $(DESTDIR)$(confdir)/mapicommd_cert.pem
	rm mapicommd_key.pem mapicommd_cert.pem
endif

# reconnection stuff
if RECONNECTION_IS_ENABLED
	${INSTALL} -m 700 reconnection.sh $(DESTDIR)$(confdir)/reconnection.sh
endif

uninstall-local:
# ssl stuff
if SSL_IS_ENABLED
	rm -f $(DESTDIR)$(confdir)/mapicommd_key.pem
	rm -f $(DESTDIR)$(confdir)/mapicommd_cert.pem
endif

# reconnection stuff
if RECONNECTION_IS_ENABLED
	rm -f $(DESTDIR)$(confdir)/reconnection.sh
endif

EXTRA_DIST = createlib.pl funct_template.c mapicommd_cert.cnf reconnection.sh
