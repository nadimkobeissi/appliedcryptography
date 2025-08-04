MAKEFLAGS += -j8
TARGETS = password-manager secure-messenger zk-battleship proverif pq-migration

all: $(TARGETS)

$(TARGETS):
	@tectonic -o ../../website/labs "$@.tex" && qpdf --linearize "../../website/labs/$@.pdf" --replace-input
