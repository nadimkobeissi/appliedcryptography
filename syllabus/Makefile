MAKEFLAGS += -j8

syllabus:
	@tectonic -o ../website/syllabus "syllabus.tex" && qpdf --linearize "../website/syllabus/syllabus.pdf" --replace-input
