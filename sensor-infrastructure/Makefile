.PHONY: provision capture

provision:
	ansible-playbook site.yml --ask-become-pass

capture:
	ansible sensor -b -m command -a 'netforge-tpot-capture /var/lib/netforge-evidence' --ask-become-pass

