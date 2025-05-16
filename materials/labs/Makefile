all:
	@make password-manager
	@make secure-messenger
	@make zk-battleship
	@make proverif

password-manager:
	@tectonic -o pdf "password-manager.tex"

secure-messenger:
	@tectonic -o pdf "secure-messenger.tex"

zk-battleship:
	@tectonic -o pdf "zk-battleship.tex"

proverif:
	@tectonic -o pdf "proverif.tex"

clean:
	@$(RM) pdf/*.aux pdf/*.nav pdf/*synctex.gz
