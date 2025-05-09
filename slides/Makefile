all:
	@make 1-1
	@make 1-2
	@make 1-3
	@make 1-4

clean:
	@latexmk -C;
	@rm -rf svg-inkscape

1-1:
	@latexmk -shell-escape "1-1"
	@mv "1-1.pdf" pdf/.

1-2:
	@latexmk -shell-escape "1-2.tex"
	@mv "1-2.pdf" pdf/.

1-3:
	@latexmk -shell-escape "1-3.tex"
	@mv "1-3.pdf" pdf/.

1-4:
	@latexmk -shell-escape "1-4.tex"
	@mv "1-4.pdf" pdf/.
