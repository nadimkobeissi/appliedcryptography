MAKEFLAGS += -j8
TARGETS = problem-set-1 problem-set-2 problem-set-3 problem-set-4 problem-set-5 problem-set-6 problem-set-7

all: $(TARGETS)

$(TARGETS):
	@tectonic -o ../../website/problem-sets "$@.tex" && qpdf --linearize "../../website/problem-sets/$@.pdf" --replace-input
