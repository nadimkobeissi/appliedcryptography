TARGETS = problem-set-1 problem-set-2 problem-set-3 problem-set-4

all: $(TARGETS)

$(TARGETS):
	@export SOURCE_DATE_EPOCH=1700000000 && tectonic -o ../../website/problem-sets "$@.tex" && qpdf --linearize "../../website/problem-sets/$@.pdf" --replace-input &
