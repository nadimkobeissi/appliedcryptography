TARGETS = password-manager secure-messenger zk-battleship proverif pq-migration

all: $(TARGETS)

$(TARGETS):
	@export SOURCE_DATE_EPOCH=1700000000 && tectonic -o ../../website/labs "$@.tex" && qpdf --linearize "../../website/labs/$@.pdf" --replace-input &
