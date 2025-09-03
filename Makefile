TARGETS_SLIDES = slides-1-1 slides-1-2 slides-1-3 slides-1-4 slides-1-5 slides-1-6 slides-1-7 slides-1-8 slides-2-1 slides-2-2 slides-2-3 slides-2-4 slides-2-5 slides-2-6 slides-2-7 slides-2-8 slides-2-9 slides-2-10
TARGETS_PROJECT = project-password-manager project-secure-messenger project-zk-battleship project-proverif-model project-pq-migration project-contact-discovery project-private-auth project-time-lock
TARGETS_PROBLEM_SET = problem-set-1 problem-set-2 problem-set-3 problem-set-4 problem-set-5 problem-set-6 problem-set-7 problem-set-8
TARGETS_QUIZ = quiz-1-2 quiz-1-3 quiz-1-4 quiz-1-5 quiz-1-6 quiz-1-7 quiz-1-8 quiz-2-1 quiz-2-2 quiz-2-3 quiz-2-4 quiz-2-5 quiz-2-6 quiz-2-7 quiz-2-8
TARGETS_SYLLABUS = syllabus

all: slides project problem-set quiz syllabus
slides: $(TARGETS_SLIDES)
project: $(TARGETS_PROJECT)
problem-set: $(TARGETS_PROBLEM_SET)
quiz: $(TARGETS_QUIZ)
clean:
	@$(RM) -r objects/slides/*.pdf objects/project/*.pdf objects/problem-set/*.pdf objects/syllabus/*.pdf objects/quiz/*.pdf starter-kit/target

$(TARGETS_SLIDES):
	@tectonic -o objects/slides "slides/$@.tex"

$(TARGETS_PROJECT):
	@tectonic -o objects/project "project/$@.tex"

$(TARGETS_PROBLEM_SET):
	@tectonic -o objects/problem-set "problem-set/$@.tex"

$(TARGETS_QUIZ):
	@tectonic -o objects/quiz "quiz/$@.tex"

$(TARGETS_SYLLABUS):
	@tectonic -o objects/syllabus "syllabus/$@.tex"

.PHONY: all slides project problem-set quiz clean $(TARGETS_SLIDES) $(PROJECT) $(TARGETS_PROBLEM_SET) $(TARGETS_QUIZ) $(TARGETS_SYLLABUS)
