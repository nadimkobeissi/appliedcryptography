MAKEFLAGS += -j8

TARGETS_SLIDES = slides-1-1 slides-1-2 slides-1-3 slides-1-4 slides-1-5 slides-1-6 slides-1-7 slides-1-8 slides-2-1 slides-2-2 slides-2-3 slides-2-4 slides-2-5 slides-2-6 slides-2-7 slides-2-8 slides-2-9 slides-2-10
TARGETS_LABS = lab-password-manager lab-secure-messenger lab-zk-battleship lab-proverif-model lab-pq-migration
TARGETS_PROBLEM_SETS = problem-set-1 problem-set-2 problem-set-3 problem-set-4 problem-set-5 problem-set-6 problem-set-7 problem-set-8
TARGETS_SYLLABUS = syllabus

all: slides labs problem-sets syllabus
slides: $(TARGETS_SLIDES)
labs: $(TARGETS_LABS)
problem-sets: $(TARGETS_PROBLEM_SETS)
clean: $(RM) website/slides/*.pdf website/lab/*.pdf website/problem-set/*.pdf website/syllabus/*.pdf

$(TARGETS_SLIDES):
	@tectonic -o website/slides "slides/$(patsubst slides-%,%,$@).tex" && qpdf --linearize "website/slides/$(patsubst slides-%,%,$@).pdf" --replace-input

$(TARGETS_LABS):
	@tectonic -o website/lab "lab/$(patsubst lab-%,%,$@).tex" && qpdf --linearize "website/lab/$(patsubst lab-%,%,$@).pdf" --replace-input

$(TARGETS_PROBLEM_SETS):
	@tectonic -o website/problem-set "problem-set/$@.tex" && qpdf --linearize "website/problem-set/$@.pdf" --replace-input

$(TARGETS_SYLLABUS):
	@tectonic -o website/syllabus "syllabus/$@.tex" && qpdf --linearize "website/syllabus/$@.pdf" --replace-input

.PHONY: all slides labs problem-sets clean $(TARGETS_SLIDES) $(TARGETS_LABS) $(TARGETS_PROBLEM_SETS) $(TARGETS_SYLLABUS)
