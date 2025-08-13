# Applied Cryptography

This repository contains source code of the course materials for Applied Cryptography (CMPS 297AD/396AI) at the American University of Beirut.

## Contents

- `lab`: Lab project sheets.
- `misc`: LaTeX dependencies.
- `problem-set`: Problem sets.
- `quiz`: Self-assessment quizzes.
- `slides`: Lecture slides.
- `starter-kit`: Cryptography implementations starter kit, written in Rust, for use during practical sessions.
- `syllabus`: Course syllabus.
- `website`: [Course website](https://appliedcryptography.page).

## Compiling LaTeX Materials

Before compiling any of the LaTeX materials, follow these steps:

1. **Install the fonts**: Install the fonts included in `misc/fonts` on your system.
2. **Install Tectonic**: Download and install [Tectonic](https://tectonic-typesetting.github.io/en-US/).
3. **Install qpdf**: Download and install [qpdf](https://qpdf.sourceforge.io/).

The good news is that this means that you don't need to install LaTeX!

Then:

- `make all`: Compiles all the slides, lab project sheets, problem sets and the syllabus.
- `make slides`: Compiles all the slides.
- `make labs`: Compiles all the lab project sheets.
- `make problem-sets`: Compiles all the problem sets.
- `make quizzes`: Compiles all the self-assessment quizzes.
- `make syllabus`: Compiles the syllabus.
- `make clean`: Deletes all compiled PDF output.

You can also do stuff like this:

- `make slides-2-4`: Compiles only Slides 2.4.
- `make lab-proverif-model`: Compiles only the ProVerif modeling lab project sheet.
- `make problem-set-4`: Compiles only Problem Set 4.
- `make quiz-1-8`: Compiles only the self-assessment quiz for topic 1.8.

You get the drift.

All compiled output PDFs will be in their respective directory in the `website` folder:

- `website/slides` contains the compiled slides PDFs.
- `website/lab` contains the compiled lab project sheet PDFs.
- `website/problem-set` contains the compiled problem set PDFs.
- `website/quiz` contains the compiled self-assessment quiz PDFs.
- `website/syllabus` contains the compiled syllabus PDF.

_It really is that simple!_

## Author & License

Applied Cryptography at the American University of Beirut by Nadim Kobeissi is licensed under Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International License.
