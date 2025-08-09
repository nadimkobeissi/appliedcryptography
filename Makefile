MAKEFLAGS += -j8

TARGETS_SLIDES = slides-1-1 slides-1-2 slides-1-3 slides-1-4 slides-1-5 slides-1-6 slides-1-7 slides-1-8 slides-2-1 slides-2-2 slides-2-3 slides-2-4 slides-2-5 slides-2-6 slides-2-7 slides-2-8 slides-2-9 slides-2-10
TARGETS_LAB = lab-password-manager lab-secure-messenger lab-zk-battleship lab-proverif-model lab-pq-migration lab-contact-discovery lab-private-auth lab-time-lock
TARGETS_PROBLEM_SET = problem-set-1 problem-set-2 problem-set-3 problem-set-4 problem-set-5 problem-set-6 problem-set-7 problem-set-8
TARGETS_QUIZ = quiz-1-2 quiz-1-3 quiz-1-4 quiz-1-5 quiz-1-6 quiz-1-7 quiz-1-8 quiz-2-1 quiz-2-2 quiz-2-3 quiz-2-4 quiz-2-5 quiz-2-6 quiz-2-7 quiz-2-8
TARGETS_SYLLABUS = syllabus

all: slides labs problem-sets quizzes syllabus
slides: $(TARGETS_SLIDES)
labs: $(TARGETS_LAB)
problem-sets: $(TARGETS_PROBLEM_SET)
quizzes: $(TARGETS_QUIZ)
clean:
	@$(RM) website/slides/*.pdf website/lab/*.pdf website/problem-set/*.pdf website/syllabus/*.pdf website/quiz/*.pdf

$(TARGETS_SLIDES):
	@tectonic -o website/slides "slides/$@.tex" && qpdf --linearize "website/slides/$@.pdf" --replace-input

$(TARGETS_LAB):
	@tectonic -o website/lab "lab/$@.tex" && qpdf --linearize "website/lab/$@.pdf" --replace-input

$(TARGETS_PROBLEM_SET):
	@tectonic -o website/problem-set "problem-set/$@.tex" && qpdf --linearize "website/problem-set/$@.pdf" --replace-input

$(TARGETS_QUIZ):
	@tectonic -o website/quiz "quiz/$@.tex" && qpdf --linearize "website/quiz/$@.pdf" --replace-input

$(TARGETS_SYLLABUS):
	@tectonic -o website/syllabus "syllabus/$@.tex" && qpdf --linearize "website/syllabus/$@.pdf" --replace-input

.PHONY: all slides labs problem-sets quizzes clean $(TARGETS_SLIDES) $(TARGETS_LAB) $(TARGETS_PROBLEM_SET) $(TARGETS_QUIZ) $(TARGETS_SYLLABUS)
