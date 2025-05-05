all:
	@make 1.1
	@make 1.2

1.1:
	@latexmk -C;
	@latexmk "1.1 - Introduction.tex";
	@mv "1.1 - Introduction.pdf" pdf/.
	@latexmk -C;

1.2:
	@latexmk -C;
	@latexmk "1.2 - One-Time Pad & The Provable Security Mindset.tex"
	@mv "1.2 - One-Time Pad & The Provable Security Mindset.pdf" pdf/.
	@latexmk -C;
