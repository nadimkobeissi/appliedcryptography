MAKEFLAGS += -j8
TARGETS = syllabus

all: $(TARGETS)

$(TARGETS):
	@tectonic -o ../website/syllabus "$@.tex" && qpdf --linearize "../website/syllabus/$@.pdf" --replace-input
